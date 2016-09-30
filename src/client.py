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

# Author: Martin Bajanik
# Date: 30.09.2016

def _initialize_connection_to_server(tcp_ip, tcp_port):
    BUFFER_SIZE = 1024

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

    _initialize_connection_to_server(args.tcp_ip, int(args.tcp_port))