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
"""

import argparse
from ctypes import c_char
import json
import threading
import re
import socket
import sys
import textwrap
import time
import uuid

# Own modules
import brute_force

__author__ = "Martin Bajanik"
__date__   = "13.10.2016"
__email__  = "396204@mail.muni.cz"
__status__ = "Development"

def connect_to_server(tcp_ip, tcp_port, found):
    global shutdown_flag
    password = None

    while not found:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
            shutdown_flag = True
            exit(1)

        found, password = init(data["data"], data["passwords"])

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((tcp_ip, tcp_port))
        client.sendall(prepare_message(found, password))
        client.shutdown(socket.SHUT_WR)
        client.close()
    except socket.error: 
        print "Connection was refused by the server."
        shutdown_flag = True
        exit(1)

    # In case password is found, set the flag so hearthbeat can stop.
    print "Exiting..."
    shutdown_flag = True

def prepare_message(found, password, hearthbeat = False):
    data = {}
    if (not hearthbeat):
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

def init(input_data, passwords):
    # Here is custom brute-forcing core called. In this case it is brute_force.py
    # In general can be anything hashcat, john etc.
    if (not input_data):
        print "Empty data received from server."
        return

    if (not passwords):
        print "No passwords provided by server."
        return

    result = brute_force.init(input_data, 0, passwords)

    # TO DO: This is to make sure, the killed flag is set to True after the heartbeat stops.
    # This is a weird workaround, should be ideally done in a way nicer way.
    time.sleep(1); 
    if (shutdown_flag):
        exit(1)

    results = result.split(':')

    print "Finished brute-force attack. Sending the results to server."
    return int(results[0]), results[1]

def hearthbeat(tcp_ip):
    while True:
        try:
            # Hearth beats are sent every ~60 seconds.
            for i in range(10):
                if shutdown_flag:
                    return
                time.sleep(1)
        except KeyboardInterrupt:
            return
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((tcp_ip, 31337))   
            client.sendall(prepare_message(None, None, True))
            client.shutdown(socket.SHUT_WR)
            json_data = recvall(client)
            if (not json_data):
                print "No data received from server. Exiting."
                return

            data = json.loads(json_data)
            client.close()
        except socket.error: 
            print "Connection was refused by the server."
            return

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
    global shutdown_flag
    shutdown_flag = False

    t = threading.Thread(target=connect_to_server, name="Password finder", args=(args.tcp_ip, int(args.tcp_port), False))
    t.start()

    hearthbeat(args.tcp_ip)
    shutdown_flag = True
    # There is probably no easy way to kill the brute_force.init() call so we can exit right away.
    t.join()