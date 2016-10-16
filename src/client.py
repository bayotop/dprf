#!/usr/bin/env python

""" Distributed Document Password Brute-Force Framework Client
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
        - Implement status checking in separate thread, to ask the server if any other client
            already found the correct password.
        - Refactor connect_to_server -> init -> connect_to_server flow. 
"""

import argparse
from ctypes import c_char
import json
import re
import socket
import sys
import textwrap
import uuid

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
    
        client.sendall(prepare_message(found, password))
        client.shutdown(socket.SHUT_WR)
        if (not found):
            json_data = recvall(client)
            if (not json_data):
                print "No data received from server. Exiting."
                return
            print "Received data. Initializing brute-force..."
            data = json.loads(json_data)
        client.close()
    except socket.error: 
        print "Connection was refused by the server."
        exit(1)

    if (not found):
        init(tcp_ip, tcp_port, data["data"], data["passwords"])

def prepare_message(found, password):
    data = {}
    data["found"] = True if found else False
    data["correct_password"] = password if password else ""
    data["id"] = identifier
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

def init(tcp_ip, tcp_port, input_data, passwords):
    # Here is custom brute-forcing core called. In this case it is brute_force.py
    # In general can be anything hashcat, john etc.
    if (not input_data):
        print "Empty data received from server."
        return

    if (not passwords):
        print "No passwords provided by server."
        return

    result = brute_force.init(input_data, 0, passwords)

    results = result.split(':')

    print "Finished brute-force attack. Sending the results to server."

    if int(results[0]):
        connect_to_server(tcp_ip, tcp_port, True, results[1])
    else:       
        connect_to_server(tcp_ip, tcp_port, False)

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
                3: Portable Document Format

            Actually supported formats:
                Office Document Structure - EncryptionInfo Stream (Standard Encryption) (Office 2007)
                OpenDocument - v1.2 with AES-256 in CBC mode
                Portable Document Format - PDF 1.3 - 1.7 (Standard Security Handlers v1-5 r2-6)
            """))

    parser.add_argument("tcp_ip", help="IP of the synchronization server")
    parser.add_argument("tcp_port", help="port on which synchronization server is listening")
    args = parser.parse_args()

    global identifier
    identifier = str(uuid.uuid4())

    connect_to_server(args.tcp_ip, int(args.tcp_port), False)