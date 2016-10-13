#!/usr/bin/env python

""" Distributed Document Password Brute-Force Framework Client
    Version 0.0.1 (alfa)

    Document types:
        1: Microsoft Office
        2: OpenDocument

    Actually supported formats:
        Office Document Structure - EncryptionInfo Stream (Standard Encryption) (Office 2007)
        OpenDocument - v1.2 with AES-256 in CBC mode

    Known Issues:
        - Implement status checking in separate thread, to ask the server if any other client
            already found the correct password.
"""

import argparse
from ctypes import c_char
import json
import re
import signal
import socket
import sys
import textwrap

# Own modules
import brute_force

__author__ = "Martin Bajanik"
__date__   = "13.10.2016"
__email__  = "396204@mail.muni.cz"
__status__ = "Development"

def connect_to_server(tcp_ip, tcp_port, found, password = None):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((tcp_ip, tcp_port))
    except: 
        print "Connection was refused by the server."
        exit(1);

    client.sendall(prepare_message(found, password))
    client.shutdown(socket.SHUT_WR)
    if (not found):
        json_data = recvall(client)
        print "Received data:"
        print json_data
        data = json.loads(json_data)

    client.close()

    if (not found):
        init(tcp_ip, tcp_port, data["data"], data["password_range"])

def prepare_message(found, password):
    data = {}
    data["found"] = True if found else False
    data["correct_password"] = password if password else ""
    return json.dumps(data)

def recvall(connection):
    # Need to be sure we read all data that is comming (best practice)
    chunks = []
    while True:
        try:
           chunk = connection.recv(1 << 12)
        except socket.timeout:
            pass
        else:
            if chunk:
                chunks.append(chunk)
            else:
                return b"".join(chunks)

def init(tcp_ip, tcp_port, input_data, password_range):
    # Here is custom brute-forcing core called. In this case it is brute_force.py
    # In general can be anything hashcat, john etc.
    if (not input_data):
        print "Empty data received from server."
        return

    result = brute_force.init(input_data, password_range);

    results = result.split(':')

    print "Finished brute-force attack. Sending the results to server."

    if int(results[0]):
        connect_to_server(tcp_ip, tcp_port, True, results[1])
    else:       
        connect_to_server(tcp_ip, tcp_port, False);

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="DDPBFC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Distributed Document Password Brute-Force Framework Client
            Version 0.0.1 (alfa)

            Document types:
                1: Microsoft Office
                2: OpenDocument

            Actually supported formats:
                Office Document Structure - EncryptionInfo Stream (Standard Encryption) (Office 2007)
                OpenDocument - v1.2 with AES-256 in CBC mode
            """))

    parser.add_argument("tcp_ip", help="IP of the synchronization server")
    parser.add_argument("tcp_port", help="port on which synchronization server is listening")
    args = parser.parse_args()

    connect_to_server(args.tcp_ip, int(args.tcp_port), False)