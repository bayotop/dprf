#!/usr/bin/env python

""" Document Password Brute-Forcer
    Version 0.0.1 (alfa)

    Document types:
        1: Microsoft Office
        2: OpenDocument
        3: Portable Document Format 

    Actually supported formats:
        Office Document Structure - EncryptionInfo Stream (Standard Encryption) (Office 2007)
        OpenDocument - v1.2 with AES-256 in CBC mode
        Portable Document Format - PDF 1.3 - 1.7 (Standard Security Handlers v1-5 r2-6)

    More to implement:
        - Support for more formats (Office 2015, older ODT versions, ...)
        - Implement owner password support for PDF
        - Needs refactoring.
"""

import argparse
from ctypes import c_char
import itertools
import multiprocessing
from multiprocessing import Process, JoinableQueue, Value, Array
import re
import string
import sys
from subprocess import Popen, check_output 
import time
import textwrap
from Queue import Empty

__author__ = "Martin Bajanik"
__date__   = "21.10.2016"
__email__  = "396204@mail.muni.cz"
__status__ = "Development"

def init(stream, password_range, passwords): 
    # The common entry point
    # Need to determine whether range or list based brute-force should be started
    if (not password_range and not passwords):
        raise ValueError('Need to provide a password range to generate or a list of passwords.')
    if (password_range and passwords):
        raise ValueError('Need to provide either a password range or a password list (not both).')

    input_data = parse_verification_data(stream)
    print "Initializing brute-force. Updates after each 1000 hashes ..."

    try:
        if (password_range and not passwords):
            return init_rangebased_brute_force(input_data, password_range)

        if (passwords and not password_range):
            return init_listbased_brute_force(input_data, passwords)
    except KeyboardInterrupt:
        sys.exit(0)  

# In case of the range based attack the actual passwords are generated in a seperate process, within this script
def init_rangebased_brute_force(input_data, password_range):   
    q = JoinableQueue()
    counter = Value('i', 0)
    found = Value('b', False)
    password = Array(c_char, "default_password_allocation") # TO DO: Password should not be longer then this. Need a better solution

    t = Process(target=_generate, name="Password Generator", args=(q, password_range, found))
    t.daemon = True
    t.start()

    for i in range(4):
        t = Process(target=_brute_force, name="Brute-Force Core " + str(i), args=(q, counter, found, input_data, password))
        t.daemon = True
        t.start()

    # Make sure something is put on queue before q.join() is called
    q.put("_dummy")
    q.join()

    return found.value, password.value

# In case of the list based attack a password list has to be provided as parameter 'passwords'
def init_listbased_brute_force(input_data, passwords):
    q = JoinableQueue()
    counter = Value('i', 0)
    found = Value('b', False)
    password = Array(c_char, "default_password_allocation") # TO DO: Password should not be longer then this. Need a better solution

    # Fill the passwords into a joinable queue
    for i in passwords:
        q.put(i)

    for i in range(4):
        t = Process(target=_brute_force, name="Brute-Force Core " + str(i), args=(q, counter, found, input_data, password))
        t.daemon = True
        t.start()

    try:
        q.join()
    except KeyboardInterrupt:
        q.join() # This second q.join is neccessary, as otherwise the script gets stuck on KeyboardInterrupt
        print "The brute-forcing was terminated by user..."
        sys.exit(0)

    return found.value, password.value

def _brute_force(q, counter, found, input_data, password):
    start = time.time()
    try:
        # The cycle is broken in case there are no passwords left in the queue or the correct password is found
        while True:
            # No point in trying when password was found. Force q.join() so we can send password to server
            if (found.value):
                _force_queue_join(q)
                return

            try:
                pwd = q.get(True, 1)
                q.task_done()
            except Empty:
                return 

            # Launch the correct brute-force core
            if (input_data[0] == "office"):
                p = _call_msoffcrypto_core(pwd, input_data)
            if (input_data[0] == "odt"):
                p = _call_odt_core(pwd, input_data)
            if (input_data[0] == "pdf"):
                p = _call_pdf_core(pwd, input_data)
            try: 
                result = p.wait()
            except KeyboardInterrupt:
                try:
                    p.terminate()
                except OSError:
                    pass
                finally:
                    _force_queue_join(q)
                    return

            if (result):
                with found.get_lock():
                    found.value = True
                    password.value = pwd
                    print("Correct password is '" + pwd + "'")
                # Force q.join() to be triggered
                # TO DO: Find a nicer way
                _force_queue_join(q)
                return

            with counter.get_lock():
                counter.value += 1

            if (counter.value != 0 and (counter.value % 1000 == 0)):
                actual = time.time()
                speed = 1 / (actual - start) * counter.value
                print "Running time: " + str(actual - start) + " & tried since: " + str(counter.value) + " passes"
                print "Speed: " + str(speed) + " H/sec"
                print "Queue size: " + str(q.qsize())
    except KeyboardInterrupt:
        _force_queue_join(q)
        return
    return

def _call_msoffcrypto_core(pwd, input_data):
    return Popen(["ms-offcrypto-impl/./msoffcrypto", pwd, 
        input_data[5], # salt
        input_data[4], # salt_length
        input_data[6], # encrypted_verifier
        str(len(input_data[6]) / 2), # encrypted_verifier_length
        input_data[7], # encrypted_verifier_hash
        str(len(input_data[7]) / 2), # encrypted_verifier_hash_length
        str(input_data[3]), # aes_key_length
        str(input_data[2]), # verifier_hash_size
        ])

def _call_odt_core(pwd, input_data):
    return Popen(["odt-impl/./odt", pwd, 
        input_data[2], # checksum
        input_data[3], # iv
        input_data[4], # salt
        input_data[5], # encrypted_file
        str(input_data[6]), # encrypted_file_length
        ]) 

def _call_pdf_core(pwd, input_data):
    return Popen(["pdf-impl/./pdf", pwd, 
        input_data[1], # version
        input_data[2], # revision
        input_data[3], # length
        input_data[4], # p
        input_data[5], # meta_encrypted 
        input_data[6], # id_length 
        str(input_data[7]), # id
        input_data[8], # u_length 
        str(input_data[9]), # u 
        input_data[10], # o_length
        str(input_data[11]) # o
        ]) 

def _generate(q, password_range, found): 
    # repeat=1 => a-z
    # repeat=2 => aa-zz
    # repeat=8 => aaaaaaaa-zzzzzzzz
    try:
        #counter = 0 
        for s in itertools.imap(''.join, itertools.product(string.lowercase, repeat=password_range)):
            # Make sure we can easily force q.join when password is found
            while (q.qsize() > 5000):
                time.sleep(2)
            # TO DO: Find a better way to cancel generating after password is found
            if (found.value):
                _force_queue_join(q)
                return
            # Test scenario when password is generated
            #if (counter == 1829):
               #q.put('password')
            #counter += 1
            q.put(s)
    except KeyboardInterrupt:
        _force_queue_join(q)
        return

# Makes sure q.join() is triggered eventually to correctly terminate the script
def _force_queue_join(q):
    print multiprocessing.current_process().name + " cleaning up..."
    while q.qsize() != 0:
        try:
            q.get(True, 1)
            q.task_done()
        except Empty:
            return 

# Parses the input file to get data neccessary to verify the password
def get_verification_data(doc_type, filename):
    print "Parsing " + filename + " ..."
 
    # TO DO: Refactor this to properly include this python scripts instead of using check_output
    if (doc_type == '1'):
        return check_output(["python", "ms-offcrypto-impl/office2john.py", filename]).strip()

    if (doc_type == '2'):
        return check_output(["python", "odt-impl/odt2hashes.py", "-e", filename]).strip()

    if (doc_type == '3'):
        return check_output(["python", "pdf-impl/pdf2john.py", filename]).strip()

# Prepares the data in a format thats understandable by the verifiers written in C
def parse_verification_data(stream):
    print "Preparing verification data ..."

    data_array = re.split("(?:\*)", stream)

    data_format = re.search(".*:\$(\w+)\$", data_array[0]).groups()[0]
    data_array[0] = data_format


    if (data_format == "office" and len(data_array) == 8):  
        return data_array

    if (data_format == "odt" and len(data_array) == 7):
        return data_array

    if (data_format == "pdf" and len(data_array) == 12):
        return data_array

    print "The input data is not supported."
    exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="DPBF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Document Password Brute-Forcer
            Version 0.0.1 (alfa)

            Document types:
                1: Microsoft Office
                2: OpenDocument
                3: Portable Document Format

            Actually supported formats:
                Office Document Structure - EncryptionInfo Stream (Standard Encryption) (Office 2007)
                OpenDocument - v1.2 with AES-256 in CBC mode
                Portable Document Format - PDF 1.3 - 1.7 (Standard Security Handlers v1-5 r2-6)
            """))

    parser.add_argument("document_type", help="type of the protected document")
    parser.add_argument("filename", help="the protected document")
    parser.add_argument("-pr", "--passwordrange", type=int, help="password range to brute-force (i.e., 2 -> aa..zz)")
    args = parser.parse_args()

    stream = get_verification_data(args.document_type, args.filename)

    if (not stream):
        sys.exit(0)

    found, password = init(stream, args.passwordrange if args.passwordrange else 8, None)

    if (not found):
        print "Password is not in brute-forced space."
