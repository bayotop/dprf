#!/usr/bin/env python
import time
#import msoffcrypto_password_verifier
from Queue import Empty
from multiprocessing import Process, JoinableQueue, Value
import string 
import itertools
from subprocess import call

# Author: Martin Bajanik
# Date: 27.08.2016

def _init():
    q = JoinableQueue()
    counter = Value('i', 0)
    found = Value('b', False)

    t = Process(target=_generate, args=(q, found))
    t.start()

    for i in range(4):
        t = Process(target=_brute_force, args=(q, counter, found) )
        t.Daemon = True
        t.start()
    
    # Make sure something is put on queue before q.join() is called. 
    q.put('dummy')
    q.join()

    if (not found.value):
        print "Password is not in brute-forced space."

def _brute_force(q, counter, found):
    start = time.time()
    #ei = msoffcrypto_password_verifier.parse_ei_file("EncryptionInfo")

    while True:
        try:
            pwd = q.get(True, 1)
        except Empty:
            return
        else:
            #result = msoffcrypto_password_verifier.verify_password(ei, pwd)
            #result = call(["./msoff", pwd])
            result = call(["./odt", pwd])
            q.task_done()

            if (result):
                with found.get_lock():
                    found.value = True
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

            if (counter.value != 0 and (counter.value % 100 == 0)):
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

if __name__ == '__main__':
    print "Starting brute-force. Updates follow..."
    _init()

