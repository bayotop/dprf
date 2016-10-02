#!/usr/bin/env python

import socket

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
# Date: 30.09.2016

def _handle_clients(stream): 
    TCP_IP = '127.0.0.1'
    TCP_PORT = 5005
    BUFFER_SIZE = 1024  # Normally 1024, but we want fast response

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen(1)


    while True:
        conn, addr = s.accept()
        print 'Connection address:', addr 
        while 1:
            data = conn.recv(BUFFER_SIZE)
            if not data: break
            print "Client connected:", data
            conn.send(stream)  # echo
        conn.close()

def _get_verification_data(doc_type, filename):
    print 'Parsing ' + filename + ' ...'
 
    if (doc_type == '1'):
        return check_output(["python", "ms-offcrypto-impl/office2john.py", filename]).strip()


    if (doc_type == '2'):
        return check_output(["python", "odt-impl/odt2hashes.py", "-e", filename]).strip()

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

    print 'Initializing brute-force engine (updates after every 1000 processed hashes) ...'
    _handle_clients(stream)
