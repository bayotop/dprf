#!/usr/bin/env python

""" Distributed Document Password Brute-Force Framework Server
    Version 0.0.1 (alfa)

    Document types:
        1: Microsoft Office
        2: OpenDocument

    Actually supported formats:
        Office Document Structure - EncryptionInfo Stream (Standard Encryption) (Office 2007)
        OpenDocument - v1.2 with AES-256 in CBC mode

    More to implement:
        - Keeping state of password ranges being brute-forced, 
            i.e. every client gets different password to generate (must have)
        - Implement state of clients. The server should know how many clients are connected
            how many password are already processed, estimate remaining time etc. 
"""

import argparse
import json
import socket
from subprocess import check_output
import textwrap

__author__ = "Martin Bajanik"
__date__   = "06.10.2016"
__email__  = "396204@mail.muni.cz"
__status__ = "Development"

def run_server(tcp_ip, tcp_port, message): 
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((tcp_ip, tcp_port))
    server.listen(5)

    while True:
        try:
            client, address = server.accept()
        except KeyboardInterrupt:
            print "Stoping server ..."
            server.close()
            return

        if (handle_connection(client, address)):
            server.close()
            break;

def handle_connection(client, address):
    found = False;

    print "A client connected from address:", address 
    json_data = recvall(client)
    client.shutdown(socket.SHUT_RD)
    print "Received data: ", json_data
    data = json.loads(json_data)

    if (data["found"]):
        print "Correct password is: ", data["correct_password"]
        found = True
    else:
        client.sendall(message)
        print "Sent new instruction to: ", address
    
    client.close()
    return found

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

def prepare_data_for_transfer(stream):
    data = {}
    data["data"] = stream
    data["password_range"] = 2
    return json.dumps(data)

def get_verification_data(doc_type, filename):
    print "Parsing " + filename + " ..."
 
    # TO DO: Refactor this to properly include this python scripts instead of using check_output
    if (doc_type == '1'):
        return check_output(["python", "ms-offcrypto-impl/office2john.py", filename]).strip()

    if (doc_type == '2'):
        return check_output(["python", "odt-impl/odt2hashes.py", "-e", filename]).strip()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="DDPBFS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            Distributed Document Password Brute-Force Framework Server
            Version 0.0.1 (alfa)

            Document types:
                1: Microsoft Office
                2: OpenDocument

            Actually supported formats:
                Office Document Structure - EncryptionInfo Stream (Standard Encryption) (Office 2007)
                OpenDocument - v1.2 with AES-256 in CBC mode
            """))

    parser.add_argument("document_type", help="type of the protected document (MS Office / OpenDocument)")
    parser.add_argument("filename", help="the protected document")
    parser.add_argument("tcp_ip", help="IP address to which clients should connect")
    parser.add_argument("tcp_port", help="port to which clients should connect")
    args = parser.parse_args()

    stream = get_verification_data(args.document_type, args.filename)
    message = prepare_data_for_transfer(stream)

    print "Running server and expecting clients to ask for data ..."
    run_server(args.tcp_ip, int(args.tcp_port), message)

