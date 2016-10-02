#!/usr/bin/env python

import socket

import time
import argparse
import textwrap
import re
from Queue import Empty
from multiprocessing import Process, JoinableQueue, Value, Array
from subprocess import call
import string 
import itertools
from ctypes import c_char
# Author: Martin Bajanik
# Date: 30.09.2016

global tcp_ip
global tcp_port

def _initialize_connection_to_server():
    BUFFER_SIZE = 1024
    global tcp_ip
    global tcp_port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((tcp_ip, tcp_port))
    except: 
        print 'Connection was refused by the server.'
        exit(1);

    s.send("1") # This should be something to identify this client. 
    data = s.recv(BUFFER_SIZE)
    s.close()

    print "received data:", data

    input_data = _parse_verification_data(data)
    _init(input_data)

def _send_result_to_server(found, correct_password = ""):
    BUFFER_SIZE = 1024
    global tcp_ip
    global tcp_port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((tcp_ip, tcp_port))
    except: 
        print 'Connection was refused by the server.'
        exit(1);

    s.send(str(found) + ":" + correct_password)
    data = s.recv(BUFFER_SIZE)
    s.close()

    if (not found):
        input_data = _parse_verification_data(data)
        _init(input_data)


def _init(input_data):  
    q = JoinableQueue()
    counter = Value('i', 0)
    found = Value('b', False)
    password = Array(c_char, "default_password_allocation") # password should not be longer then this.

    t = Process(target=_generate, args=(q, found))
    t.start()

    for i in range(4):
        t = Process(target=_brute_force, args=(q, counter, found, input_data, password))
        t.Daemon = True
        t.start()
    
    # Make sure something is put on queue before q.join() is called. 
    q.put('dummy')
    q.join()

    print "Done. Sending results."
    if (not found.value):
        _send_result_to_server(False);
    else:       
        _send_result_to_server(True, password.value);

def _brute_force(q, counter, found, input_data, password):
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
                    str(len(input_data[6]) / 2), # encrypted_verifier_length
                    input_data[7], # encrypted_verifier_hash
                    str(len(input_data[7]) / 2), # encrypted_verifier_hash_length
                    str(input_data[3]), # aes_key_length
                    str(input_data[2]), # verifier_hash_size
                    ]) 
            if (input_data[0] == "odt"):
                result = call(["odt-impl/./odt", pwd, 
                    input_data[2], #checksum
                    input_data[3], #iv
                    input_data[4], #salt
                    input_data[5], #encrypted_file
                    str(input_data[6]), #encrypted_file_length
                   ]) 
            q.task_done()

            if (result):
                with found.get_lock():
                    found.value = True
                    password.value = pwd
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


def _parse_verification_data(stream):
    print 'Preparing verification data ...'

    data_array = re.split('(?:\*)', stream)

    data_format = re.search('.*:\$(\w+)\$', data_array[0]).groups()[0]
    data_array[0] = data_format


    if (data_format == "office" and len(data_array) == 8):  
        return data_array

    if (data_format == "odt" and len(data_array) == 7):
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

    parser.add_argument('tcp_ip', help='IP of the synchronization server')
    parser.add_argument('tcp_port', help='port on which synchronization server is listening')
    args = parser.parse_args()

    global tcp_ip
    tcp_ip = args.tcp_ip
    global tcp_port
    tcp_port = int(args.tcp_port)

    _initialize_connection_to_server()