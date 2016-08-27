#!/usr/bin/env python
import time
import argparse
import textwrap
import re
from Queue import Empty
from multiprocessing import Process, JoinableQueue, Value
import string 
import itertools
from subprocess import call, check_output

# Author: Martin Bajanik
# Date: 27.08.2016

def _init(input_data):  
    q = JoinableQueue()
    counter = Value('i', 0)
    found = Value('b', False)

    t = Process(target=_generate, args=(q, found))
    t.start()

    for i in range(4):
        t = Process(target=_brute_force, args=(q, counter, found, input_data))
        t.Daemon = True
        t.start()
    
    # Make sure something is put on queue before q.join() is called. 
    q.put('dummy')
    q.join()

    if (not found.value):
        print "Password is not in brute-forced space."

def _brute_force(q, counter, found, input_data):
    start = time.time()

    while True:
        try:
            pwd = q.get(True, 1)
        except Empty:
            return
        else:
            if (input_data[0] == "office"):
                result = call(["ms-offcrypto-impl/./msoffcrypto", pwd, 
                    input_data[5], # salt
                    input_data[4], # salt_length
                    input_data[6], # encrypted_verifier
                    str(len(input_data[6])), # encrypted_verifier_length
                    input_data[7], # encrypted_verifier_hash
                    str(len(input_data[7])), # encrypted_verifier_hash_length
                    str(input_data[3]), # aes_key_length
                    str(input_data[2]) # verifier_hash_size
                    ]) 
            if (input_data[0] == "odt"):
                result = call(["odt-impl/./odt", pwd, 
                    input_data[2], #checksum
                    input_data[3], #iv
                    input_data[4], #salt
                    input_data[5], #encrypted_file
                    str(len(input_data[5]))]) #encrypted_file_length

            q.task_done()

            if (result):
                with found.get_lock():
                    found.value = True
                    print("Correct password is '" + pwd + "'")
                    # Force q.join() to be triggered
                    # TO DO: find a nicer way 
                    while q.qsize != 0:
                        try:
                            q.get(True, 1)
                            q.task_done()
                        except Empty:
                            return

            with counter.get_lock():
                counter.value += 1

            if (counter.value != 0 and (counter.value % 1000 == 0)):
                actual = time.time()
                speed = 1 / (actual - start) * counter.value
                print "Running time: " + str(actual - start) + " & tried since: " + str(counter.value) + " passes"
                print "Speed: " + str(speed) + " H/sec"
                print "Queue size: " + str(q.qsize())
            
    return

def _generate(q, found):   
    #q.put('password') # Test scenario when password is generated
    # repeat=1 => a-z
    # repeat=2 => aa-zz
    # repeat=8 => aaaaaaaa-zzzzzzzz   
    for s in itertools.imap(''.join, itertools.product(string.lowercase, repeat=8)):
         # TO DO: Find a better way to cancel generating after password is found
        if (found.value):
            break
        q.put(s)

def _get_verification_data(doc_type, filename):
    print 'Parsing ' + filename + ' ...'
 
    if (doc_type == '1'):
        return check_output(["python", "ms-offcrypto-impl/office2john.py", filename]).strip()


    if (doc_type == '2'):
        return check_output(["python", "odt-impl/odt2hashes.py" ,"-e", filename]).strip()

def _parse_verification_data(stream):
    print 'Preparing verification data ...'

    data_array = re.split('(?:\*)', stream)

    data_format = re.search('.*:\$(\w+)\$', data_array[0]).groups()[0]
    data_array[0] = data_format


    if (data_format == "office" and len(data_array) == 8):
        data_array[5] = data_array[5].decode('hex');  
        data_array[6] = data_array[6].decode('hex');  
        data_array[7] = data_array[7].decode('hex');  

        return data_array

    if (data_format == "odt" and len(data_array) == 6):
        data_array[2] = data_array[2].decode('hex');  
        data_array[3] = data_array[3].decode('hex');  
        data_array[4] = data_array[4].decode('hex'); 
        data_array[5] = data_array[5].decode('hex');

        return data_array

    print "The input data is not supported."
    exit(1); 

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='DDPBF',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
            Distributed Document Password Brute-Force Framework
            Version 0.0.1 (alfa)

            Document types:
                1: Microsoft Office
                2: OpenDocument

            Actually supported formats:
                Office Document Structure - EncryptionInfo Stream (Standard Encryption) (Office 2007)
                OpenDocument - v1.2 with AES-256 in CBC mode
            '''))

    parser.add_argument('document_type', help='type of the protected document (MS Office / OpenDocument)')
    parser.add_argument('filename', help='the protected document')
    args = parser.parse_args()

    stream = _get_verification_data(args.document_type, args.filename)
    input_data = _parse_verification_data(stream)

    print 'Initializing brute-force engine (updates after every 1000 processed hashes) ...'
    _init(input_data)

