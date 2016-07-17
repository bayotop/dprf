#!/usr/bin/env python
import time
import msoffcrypto_password_verifier
from Queue import Empty
from multiprocessing import Process, JoinableQueue, Value
import string 
import itertools

def _brute_force():
    global counter
    global found

    while True:
        try:
            p = q.get(True, 1)
        except Empty:
            return
        else:
            result = msoffcrypto_password_verifier.verify_password(ei, p)
            q.task_done()

            if (result):
                with found.get_lock():
                    found.value = True
                    print("Correct password is '" + p + "'")
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


def _generate(length):
    # TO DO: Find a better way to cancel generating after password is found
    global found
    q.put('password') # Test scenario when password is generated
    # repeat=1 => a-z
    # repeat=2 => aa-zz
    # repeat=8 => aaaaaaaa-zzzzzzzz   
    for s in itertools.imap(''.join, itertools.product(string.lowercase, repeat=length)):
        if (found.value):
            break
        q.put(s)

if __name__ == '__main__':
    q = JoinableQueue()
    counter = Value('i', 0)
    found = Value('b', False)

    t = Process(target=_generate, args=(8,))
    t.start()

    start = time.time()
    ei = msoffcrypto_password_verifier.parse_ei_file("EncryptionInfo")
    print "Started: " + str(start)

    for i in range(4):
        t = Process(target=_brute_force)
        t.Daemon = True
        t.start()

    q.join()

    if (not found.value):
        print "Password is not in brute-forced space."

