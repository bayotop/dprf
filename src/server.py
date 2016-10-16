#!/usr/bin/env python

""" Distributed Document Password Brute-Force Framework Server
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
        - Implement state of clients. The server should know how many clients are connected
            how many password are already processed, estimate remaining time etc.
        - Implement state reporting: number of clients, number of processed passwords, 
            estimated time left, etc.
"""

import argparse
import itertools
import json
from multiprocessing import Process, JoinableQueue, Value, Array
import string
import socket
import sys
from subprocess import check_output
import textwrap
import time
from Queue import Empty

__author__ = "Martin Bajanik"
__date__   = "13.10.2016"
__email__  = "396204@mail.muni.cz"
__status__ = "Development"

global payload_size
payload_size = 20000 # TO DO: Anything larger causes brute_force.py to not terminate correctly on keyboard interrupt. 

def run_server(tcp_ip, tcp_port, stream, password_range):
    q = JoinableQueue()
    found = Value('b', False)

    t = Process(target=_generate, name="Password Generator", args=(q, password_range, found))
    t.daemon = True
    t.start()

    # Make sure we have enough passwords precomputed
    while (q.qsize() < payload_size):
        time.sleep(2)

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((tcp_ip, tcp_port))
        server.listen(5)
    except socket.error as ex:
        print "Error opening socket:", ex
        return

    # Number of total passwords sent to clients.
    counter = 0

    while True:
        print "Everything ready. Waiting for new client..."
        message = prepare_data_for_transfer(q, stream)
        try:
            client, address = server.accept()
        except KeyboardInterrupt:
            print "Stoping server ..."
            server.close()
            return

        if (handle_connection(client, address, message)):
            server.close()
            counter += payload_size
            break

def handle_connection(client, address, message):
    found = False

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

def _generate(q, password_range, found): 
    # repeat=1 => a-z
    # repeat=2 => aa-zz
    # repeat=8 => aaaaaaaa-zzzzzzzz
    #counter = 0
    try:
        for x in range(1, password_range + 1 if password_range else 9): # default is 1..8
            for s in itertools.imap(''.join, itertools.product(string.lowercase, repeat=x)):
                # Data has to be ready all the time. However, not to much, so we can easily quit and dont flood memory.
                while (q.qsize() > payload_size * 2):
                    time.sleep(2)
                # TO DO: Find a better way to cancel generating after password is found
                if (found.value):
                    _force_queue_join(q)
                    return
                # Test scenario when password is generated
                #if (counter == 21656):
                   #q.put('password')
                #counter += 1
                q.put(s)
    except:
        sys.exit(0)

def _force_queue_join(q):
    while q.qsize() != 0:
        try:
            q.get(True, 1)
            q.task_done()
        except Empty:
            return 

def prepare_data_for_transfer(q, stream):
    data = {}
    data["data"] = stream
    data["passwords"] = get_passwords(q)
    return json.dumps(data)

def get_passwords(q):
    counter = 0
    passwords = []
    while (counter < payload_size):
        try:
            passwords.append(q.get(True, 1))
            q.task_done()
            counter += 1
        except Empty:
            print "INFO: All passwords are gone."
            break
    return passwords


def get_verification_data(doc_type, filename):
    print "Parsing " + filename + " ..."

    if (doc_type == '1'):
        return check_output(["python", "ms-offcrypto-impl/office2john.py", filename]).strip()

    if (doc_type == '2'):
        return check_output(["python", "odt-impl/odt2hashes.py", "-e", filename]).strip()

    if (doc_type == '3'):
        return check_output(["python", "pdf-impl/pdf2john.py", filename]).strip()

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
                3: Portable Document Format

            Actually supported formats:
                Office Document Structure - EncryptionInfo Stream (Standard Encryption) (Office 2007)
                OpenDocument - v1.2 with AES-256 in CBC mode
                Portable Document Format - PDF 1.3 - 1.7 (Standard Security Handlers v1-5 r2-6)
            """))

    parser.add_argument("document_type", help="type of the protected document (MS Office / OpenDocument)")
    parser.add_argument("filename", help="the protected document")
    parser.add_argument("-pr", "--passwordrange", type=int, help="password range to brute-force (i.e., 2 -> aa..zz)")
    parser.add_argument("tcp_ip", help="IP address to which clients should connect")
    parser.add_argument("tcp_port", help="port to which clients should connect")
    args = parser.parse_args()

    stream = get_verification_data(args.document_type, args.filename)

    if (not stream):
        sys.exit(0)

    run_server(args.tcp_ip, int(args.tcp_port), stream, args.passwordrange)

