#!/usr/bin/env python
import shutil
import argparse
import zipfile
import tempfile
import textwrap
import base64
import xml.etree.ElementTree as et

# TODO:
#       Namespace handling when parsing XML needs refactoring, i.e:
#           urn:oasis:names:tc:opendocument:xmlns:manifest:1.0
#           urn:oasis:names:tc:opendocument:xmlns:digitalsignature:1.0
#           http://docs.oasis-open.org/ns/office/1.2/meta/pkg#


# Returns all information needed to perform offline brute-force analysis of ODT files.
# Actually supported versions:
#   ODT 1.2

# Format of returned data is:
#   
#    $odt$*version*checksum*iv*salt*encrypted_file_bytes

# Note: The encryption data of the smallest encrypted file is used. 

# Author: Martin Bajanik
# Date: 23.08.2016

class VerificationFile:
    def __init__(self, fe, size):
        self.fe = fe
        self.size = size

# Globals
verbose = False
ns = '{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}'

# $odt$*version*checksum*iv*salt*encrypted_file_bytes
hashes_template = '$odt$*{0}*{1}*{2}*{3}*{4}'

def main(args):
    global verbose
    verbose = args.verbose

    get_hashes(args.filename)

def get_hashes(filename):
    temppath = tempfile.mkdtemp()

    with zipfile.ZipFile(filename, "r") as z:
        z.extractall(temppath)

    with open(temppath + "/META-INF/manifest.xml", 'rb') as manifest:
        tree = et.parse(manifest)

    root = tree.getroot()

    version = root.get(ns + 'version')

    # Find the smalles possible encrypted file. This file shall later be used for password verification. 
    smallestfile = VerificationFile(None, None);
    for fe in root.iter(ns + 'file-entry'):
        size = fe.get(ns + 'size')
        if (size != None and (smallestfile.fe == None or size < smallestfile.size)):
            smallestfile = VerificationFile(fe, size)

    encryption_data = smallestfile.fe.find(ns + 'encryption-data')

    checksum = base64.b64decode(encryption_data.get(ns + 'checksum'))
    iv = base64.b64decode(encryption_data.find(ns + 'algorithm').get(ns + 'initialisation-vector'))
    salt = base64.b64decode(encryption_data.find(ns + 'key-derivation').get(ns + 'salt'))
    encrypted_file_bytes = None

    with open(temppath + "/" + smallestfile.fe.get(ns + 'full-path')) as f:
        encrypted_file_bytes = f.read()

    print hashes_template.format(version, checksum.encode('hex'), iv.encode('hex'), salt.encode('hex'), encrypted_file_bytes.encode('hex'))

    shutil.rmtree(temppath)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='odt2hashes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
            Returns all information needed to perform offline brute-force analysis of ODT files.
            Actually supported versions:
                ODT 1.2

            Format of returned data is:

                $odt$*version*checksum*iv*salt*encrypted_file_bytes

            Note: The encryption data of the smallest encrypted file is used. 
            '''))

    parser.add_argument('-v', '--verbose', help='increase output verbosity', default=False,
                        action='store_true')
    parser.add_argument('filename', help='path to ODT file')
    args = parser.parse_args()
    main(args)
