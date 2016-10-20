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
        - Needs refactoring.
        - If a client becomes inactive, there are possible passwords that will never be tried.
          The inactive client's data should be resend to another client ideally.
        - Implement a logger, this print shit is ridiculous.
        - Curses UI.
"""

import argparse
from datetime import datetime, timedelta
import itertools
import json
from multiprocessing import Process, JoinableQueue, Value
import string
import socket
import sys
from subprocess import check_output
import textwrap
import threading
import time
from Queue import Empty

__author__ = "Martin Bajanik"
__date__   = "13.10.2016"
__email__  = "396204@mail.muni.cz"
__status__ = "Development"

class Client:
    def __init__(self, id, last_activity):
        self.id = id
        self.last_activity = last_activity

    def __str__(self):
        return "ID: " + self.id + " Last activity: " + str(self.last_activity)

    def __eq__(self, other):
        return self.id == other.id

    def isActive(self):
        return self.last_activity > datetime.now() - timedelta(seconds=120)

    def refresh(self, last_activity):
        self.last_activity = last_activity


def run_server(tcp_ip, tcp_port, stream, password_range):
    q = JoinableQueue()
    found = Value('b', False)

    t = Process(target=generate, name="Password Generator", args=(q, password_range, found))
    t.daemon = True
    t.start()

    t = threading.Thread(target=hearthbeat, name="Hearthbeat", args=(tcp_ip, found))
    t.daemon = True
    t.start()

    t= threading.Thread(target=remove_inactive_clients, name="Client clean-up", args=())
    t.daemon = True
    t.start()

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((tcp_ip, tcp_port))
        server.listen(5)
    except socket.error as ex:
        print "Error opening socket:", ex
        return

    start_time = time.time()
    global counter
    counter = 0

    while True:     
        print "Number of clients: " + str(len(clients))
        print "Estimated speed: " + str(1 / (time.time() - start_time) * counter) + " H/sec"
        message = prepare_data_for_transfer(q, stream)
        # There are no more passwords to send, but he have to wait for all clients to finish. 
        if (not message and not clients):
            print "Password is not in brute-forced space."
            server.close()
            return
        try:
            client, address = server.accept()
        except KeyboardInterrupt:
            print "Stoping server..."
            server.close()
            return

        result, counter = handle_connection(client, address, message)
        if (result):
            with found.get_lock():
                found.value = True
            server.close()
            return

def handle_connection(client, address, message):
    global counter
    found = False

    print "A client connected from address:", address
    json_data = recvall(client)
    client.shutdown(socket.SHUT_RD)
    data = json.loads(json_data)
    client_identifier = data["id"]

    # Only handle existing connections, if there are no more passwords to try.
    if (not client_identifier in (x.id for x in clients)):
        if (message):
            clients.append(Client(client_identifier, datetime.now()))
        else:
            client.close()
            return False, counter
    # We increase the count of processed pasword, as a client is contacting us repeatedly.
    else:
        counter += payload_size

    # Check the message if the password was found. If not, send new data in case there are any.
    if (data["found"]):
        print "Correct password is: ", data["correct_password"]
        found = True
    else:
        if (message):
            client.sendall(message)
            print "Sent new instruction to: ", address
        else:
            clients.remove([c for c in clients if c.id == client_identifier][0])

    # Any both cases, close the connection. Client will only stop working, in case he gets no response. 
    client.close()
    return found, counter

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

def generate(q, password_range, found): 
    # repeat=1 => a-z
    # repeat=2 => aa-zz
    # repeat=8 => aaaaaaaa-zzzzzzzz
    counter_test = 0
    try:
        for x in range(1, password_range + 1 if password_range else 9): # default is 1..8
            for s in itertools.imap(''.join, itertools.product(string.lowercase, repeat=x)):
                # Data has to be ready all the time. However, not to much, so we can easily quit and dont flood memory.
                while (q.qsize() > payload_size * 2):
                    time.sleep(2)
                # Test scenario when password is generated
                if (counter_test == 3785):
                   q.put('password')
                counter_test += 1
                q.put(s)
    except KeyboardInterrupt:
        sys.exit(0)        

def hearthbeat(tcp_ip, found):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((tcp_ip, 31337))
        server.listen(5)
    except socket.error as ex:
        print "Error opening heartbeat socket:", ex
        return

    while True:
        try:
            client, address = server.accept()
        except KeyboardInterrupt:
            server.close()
            return

        json_data = recvall(client)
        client.shutdown(socket.SHUT_RD)
        data = json.loads(json_data)
        client_identifier = data["id"]

        if (client_identifier in (x.id for x in clients)):
            [c for c in clients if c.id == client_identifier][0].refresh(datetime.now())

        data = {}
        data["found"] = found.value
        client.sendall(json.dumps(data))
        client.close()

def remove_inactive_clients():
    while True:
        time.sleep(120)
        inactive_clients = []
        for c in clients:
            if (not c.isActive()):
                inactive_clients.append(c)

        for c in inactive_clients:
            print "Client ", c.id, " is inactive."           
            clients.remove(c)
            print "Active clietns: ", len(clients)

def prepare_data_for_transfer(q, stream):
    data = {}
    data["data"] = stream
    data["passwords"] = get_passwords(q)

    if (not data["passwords"]):
        return None 

    return json.dumps(data)

def get_passwords(q):
    counter = 0
    passwords = []
    while (counter < payload_size):
        try:
            # 5 seconds timeout. Should be more then enough as _generate() sleeps only for 2.
            passwords.append(q.get(True, 5))
            q.task_done()
            counter += 1
        except Empty:
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
    parser.add_argument("-pr", "--passwordrange", type=int, help="password range to brute-force (i.e., 2 -> aa..zz, default 8)")
    parser.add_argument("-ps", "--payloadsize", type=int, help="number of passwords sent to clients (default 20000)")
    parser.add_argument("tcp_ip", help="IP address to which clients should connect")
    parser.add_argument("tcp_port", help="port to which clients should connect")
    args = parser.parse_args()

    global payload_size
    payload_size = args.payloadsize if args.payloadsize else 20000
    global clients
    clients = []

    stream = get_verification_data(args.document_type, args.filename)

    if (not stream):
        sys.exit(0)

    run_server(args.tcp_ip, int(args.tcp_port), stream, args.passwordrange)

