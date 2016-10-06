#!/usr/bin/env python

import socket

import time
import argparse
import textwrap
import re
import json
from Queue import Empty
from multiprocessing import Process, JoinableQueue, Value
import string 
import itertools
from subprocess import call, check_output

# Author: Martin Bajanik
# Date: 06.10.2016

global buffer_size
buffer_size = 2048

def _handle_clients(message): 
    TCP_IP = '127.0.0.1'
    TCP_PORT = 5005

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen(1)

    while True:
        conn, addr = s.accept()
        print 'Connection address:', addr 
        # Need to be sure we read all data that is comming (best practive)
        chunks = []
        while True:
            chunk = conn.recv(buffer_size)
            chunks.append(chunk)
            if len(chunk) >= 40: # {"found": false, "correct_password": ""} or {"found": true, "correct_password": "x"}
                break   # We probably have all data. We cannot be sure because client didn't close the connection as we need to send him an answer
                        # This should be handled differently, but I am not quite sure what's the best practice

        json_data = b''.join(chunks)

        print "Received data:"
        print json_data

        data = json.loads(json_data)

        if (data["found"]):
            print "Correct password is: ", data["correct_password"]
            conn.close()
            break; # Actually we should keep running so we can inform other clients, that password was already found
        else:
            # Need to make sure whole message is sent (best practice)
            totalsent = 0
            while totalsent < len(message):
                sent = conn.send(message[totalsent:])
                if sent == 0:
                    raise RuntimeError("Socket connection broke while sending data.")
                totalsent = totalsent + sent
        
            conn.close()
    s.close()

def _prepare_data_for_transfer(stream):
    data = {}
    data['data'] = stream
    data['password_range'] = 3
    return json.dumps(data)

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
    message = _prepare_data_for_transfer(stream)

    print 'Initializing brute-force engine (updates after every 1000 processed hashes) ...'
    _handle_clients(message)

