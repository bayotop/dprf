#!/usr/bin/env python
from string import ascii_lowercase
import importlib
import time
import msoffcrypto_password_verifier
import sys

def _brute_force(pwd, pos):
    global count
    if (pos < 0):

        # This shouldn't be here, as it's not the generators goal to verify the password.
        # TODO: Refactor, so parallelism is possible.
        if (count != 0 and (count % 100 == 0)):
            actual = time.time()
            speed = 1 / (actual - start) * count
            print "Running time: " + str(actual - start) + " & tried since: " + str(count) + " passes"
            print "Speed: " + str(speed) + " H/sec"
            #pwd = "password";

    	if (msoffcrypto_password_verifier.verify_password(ei, pwd.decode("utf-8"))):
    		print("Correct password is '" + pwd + "'")
    		sys.exit(0)
        count += 1

        return

    # switch (pos):
    # case 1: a - z
    # case 2: aa - zz
    # ...
    # case 8: aaaaaaaa - zzzzzzzzzz    
    for pwd[pos] in range(ord('a'), ord('z') + 1):
        _brute_force(pwd, pos - 1);


count = 0
start = time.time()
ei = msoffcrypto_password_verifier.parse_ei_file("EncryptionInfo")
print "Started: " + str(start)
pwd = bytearray(2)
_brute_force(pwd, 1)
print "Password is not in brute-forced space."