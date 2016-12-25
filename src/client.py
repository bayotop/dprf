#!/usr/bin/env python

""" Distributed Document Password Brute-Force Framework Client
    Version 0.0.1

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
import re
import socket
import sys
import textwrap
import threading
import time
import uuid

# Own modules
import brute_force

__author__ = "Martin Bajanik"
__date__   = "21.10.2016"
__email__  = "396204@mail.muni.cz"
__status__ = "Development"

def connect_to_server(tcp_ip, tcp_port, found):
    password = None

    # As long as the password is not found, we ask the server to provide more data
    # In case the server, is down or returns no data (which should never happen) the client stops
    while not found:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((tcp_ip, tcp_port))
            client.sendall(prepare_message(found, password))
            client.shutdown(socket.SHUT_WR)
            json_data = recvall(client)
            if (not json_data):
                print "No data received from server. Exiting."
                exit(1);
            print "Received data. Initializing brute-force..."
            data = json.loads(json_data)
            client.close()
        except socket.error: 
            print "Can't continue with brute-force. The server seems to be down."
            exit(1)

        found, password = init(data["data"], data["passwords"])

    # Once the correct password is found we notify the server
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((tcp_ip, tcp_port))
        client.sendall(prepare_message(found, password))
        client.shutdown(socket.SHUT_WR)
        client.close()
    except socket.error: 
        print "Failed to send found password to server (connection was refused)."

def prepare_message(found, password, hearthbeat = False):
    # The message should contain the password in case found is true
    # A hearthbeat message contains only the clients ID
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
                return b''.join(chunks)

def init(input_data, passwords):
    # Here is the custom brute-forcing core called. In this case it is brute_force.py
    # In general can be anything hashcat, JtR etc.
    if (not input_data):
        print "Empty data received from server."
        return

    if (not passwords):
        print "No passwords provided by server."
        return

    found, password = brute_force.init(input_data, 0, passwords)

    print "Finished brute-force attack. Sending the results to server."
    return found, password

def hearthbeat(tcp_ip):
    while True:
        try:
            time.sleep(20)
        except KeyboardInterrupt:
            return
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((tcp_ip, 31337))   
            client.sendall(prepare_message(None, None, True))
            client.shutdown(socket.SHUT_WR)
            json_data = recvall(client) # Any reposnse means, the server is running => password is not found yet
            client.close()
        except socket.error: 
            # TO DO: Find a way to terminate the main thread (brute_force.init waits for q.join() which is not easily interruptable)
            # ATM the client will have to finish the currect chunk of passwords before exiting
            print "Hearthbeat failed. Server seems to be down."
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

    # A unique identifier identifying a concrete client instance
    global identifier
    identifier = str(uuid.uuid4())

    # Running in a separate thread the hearthbeat ensures that the server does not render the client inactive 
    # A hearthbeat is sent every 60 seconds 
    t = threading.Thread(target=hearthbeat, name="Hearthbeat", args=(args.tcp_ip,))
    t.daemon = True
    t.start()

    connect_to_server(args.tcp_ip, int(args.tcp_port), False)
