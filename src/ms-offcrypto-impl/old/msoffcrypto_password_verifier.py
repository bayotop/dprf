#!/usr/bin/env python

import argparse
from Crypto.Hash.SHA import SHA1Hash
from Crypto.Cipher import AES
import struct
import textwrap

# [MS-OFFCRYPTO] Office Document Structure - Password Verifier 
		
# Version 0.0.1 (alfa)
# Verifies correctness of given password for given EncryptionInfo.
# Actually supported formats:
# 	EncryptionInfo Stream (Standard Encryption)

# Author: Martin Bajanik
# Date: 23.08.2016

# Globals
verbose = 0

class Version:
    def __init__(self, major, minor):
       	self.Major = major
       	self.Minor = minor

class Header:
	def __init__(self, data):
		self.Flags = struct.unpack('<I', data[0:4])[0]
		self.SizeExtra = struct.unpack('<I', data[4:8])[0]
		self.AlgID = struct.unpack('<I', data[8:12])[0]
		self.AlgIDHash = struct.unpack('<I', data[12:16])[0]
		self.KeySize = struct.unpack('<I', data[16:20])[0]
		self.ProviderType = struct.unpack('<I', data[20:24])[0]
		self.Reserved1 = struct.unpack('<I', data[24:28])[0]
		self.Reserved2 = struct.unpack('<I', data[28:32])[0]
		self.CSPName = struct.unpack_from('<%ss' % (len(data)-32), data, 32)[0]

class Verifier:	
	def __init__(self, data):
		self.SaltSize = struct.unpack('<I', data[0:4])[0]
		self.Salt = data[4:20]
		self.EncryptedVerifier = data[20:36]
		self.VerifierHashSize = struct.unpack('<I', data[36:40])[0]
		self.EncryptedVerifierHash = data[40:len(data)]

class EncryptionInfo:
	def __init__(self, filename):
		ei = open(filename, 'rb')
		self.raw = ei.read()

		self.Version = Version(struct.unpack('<H', self.raw[0:2])[0], 
			struct.unpack('<H', self.raw[2:4])[0])
		self.Flags = struct.unpack('<I', self.raw[4:8])[0]
		self.HeaderSize = struct.unpack('<I', self.raw[8:12])[0]
		self.Header = Header(self.raw[12:(self.HeaderSize + 12)])
		self.Verifier = Verifier(self.raw[(self.HeaderSize + 12):len(self.raw)])

def aes_key_length_from_code(x):
	return {
		0x660E: 16, # AES-128
		0x660F: 24, # AES-192
		0x6610: 32  # AES-256 
	}[x]

def main(args):
    global verbose
    verbose = args.verbose

    ei = parse_ei_file(args.filename)
    verify_password(ei, args.password)

def parse_ei_file(filename):
    return EncryptionInfo(filename)

def verify_password(ei, password):
	if (verbose):
		_print_ei_structure(ei)

	keyDerived = _derive_key(password, ei.Verifier.Salt, ei.Header.AlgID)
	_vprint('Derived key: ' + keyDerived.encode('hex'))

	if (_verify_key(keyDerived, ei.Verifier)):
		_vprint('"%s"' % password + ' is correct!')
		return 1

	_vprint('"%s"' % password + ' is incorrect.')
	return 0

def _derive_key(password, salt, algID):
	password = password.encode('utf-16le') # UNICODE is UTF-16 LE (MS)
	hashAlgo = SHA1Hash() # SHA-1 is the only hashing algorithm specified

	pHash = hashAlgo.new(salt + password) 

	for i in xrange(50000):
		pHash = pHash.new(struct.pack('<L', i) + pHash.digest())

	pHash = pHash.new(pHash.digest() + struct.pack('<L', 0)) # block is 0x00000000
	hFinal = pHash.digest()

	_vprint('Final hash of key: ' + hFinal.encode('hex'))

	cbRequiredKeyLength = aes_key_length_from_code(algID)
	cbHash = 20 # This is always 20, as SHA-1 is the only specified

	tBuffer = bytearray([0x36] * 64)

	for x in xrange(0, cbHash):
		tBuffer[x] ^= bytearray(hFinal)[x]

	pHash = pHash.new(tBuffer)
	X1 = pHash.digest()

	_vprint('X1: ' + X1.encode('hex'))

	tBuffer = bytearray([0x5C] * 64)

	for x in xrange(0, cbHash):
		tBuffer[x] ^= bytearray(hFinal)[x]

	pHash = pHash.new(tBuffer)
	X2 = pHash.digest()

	_vprint('X2: ' + X2.encode('hex'))
	X3 = X1 + X2

	return X3[0:cbRequiredKeyLength]

def _verify_key(key, verifier):

	pCipher = AES.new(key, AES.MODE_ECB)
	verifier_bytes = pCipher.decrypt(verifier.EncryptedVerifier)

	decryptedVerifierHash = pCipher.decrypt(verifier.EncryptedVerifierHash)[0:verifier.VerifierHashSize]

	hashAlgo = SHA1Hash()
	pHash = hashAlgo.new(verifier_bytes)
	verifierHash = pHash.digest()

	_vprint('Decrypted "EncryptedVerifier" hash: ' + verifierHash.encode('hex'))
	_vprint('Decrypted "EncryptedVerifierHash":  ' + decryptedVerifierHash.encode('hex'))

	if (verifierHash == decryptedVerifierHash):
		return 1

	return 0

def _vprint(message):
	global verbose

	if (verbose):
		print(message)

def _print_ei_structure(ei):
	print ei.raw.encode('hex')
	print hex(ei.Version.Major)
	print hex(ei.Version.Minor)
	print hex(ei.Flags)
	print ei.HeaderSize
	print hex(ei.Header.Flags)
	print hex(ei.Header.SizeExtra)
	print hex(ei.Header.AlgID)
	print hex(ei.Header.AlgIDHash)
	print ei.Header.KeySize
	print hex(ei.Header.ProviderType)
	print hex(ei.Header.Reserved1)
	print hex(ei.Header.Reserved2)
	print ei.Header.CSPName
	print ei.Verifier.SaltSize
	print ei.Verifier.Salt.encode('hex')
	print ei.Verifier.EncryptedVerifier.encode('hex')
	print ei.Verifier.VerifierHashSize
	print ei.Verifier.EncryptedVerifierHash.encode('hex')
	print '--------------------------------------------------------'

if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		prog='msoffcrypto_password_verifier',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		description=textwrap.dedent('''\
			[MS-OFFCRYPTO] Office Document Structure - Password Verifier 
			
			Version 0.0.1 (alfa)
			Verifies correctness of given password for given EncryptionInfo.
			Actually supported formats:
			    EncryptionInfo Stream (Standard Encryption)
			'''))

	parser.add_argument('-v', '--verbose', help='increase output verbosity', default=False,
						action='store_true')
	parser.add_argument('filename', help='path to EncryptionInfo file')
	parser.add_argument('password', help='password to verify')
	args = parser.parse_args()
	main(args)