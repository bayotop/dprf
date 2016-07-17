#!/usr/bin/env python
from string import ascii_lowercase
import importlib
import time
import msoffcrypto_password_verifier

def _generate(pwd, pos):
    global count
    if (pos < 0):
        if (count != 0 and (count % 100 == 0)):
            actual = time.time()
            speed = 1 / (actual - start) * count
            print "Running time: " + str(actual - start) + " & tried since: " + str(count) + "passes"
            print "Speed: " + str(speed)

    	msoffcrypto_password_verifier.verify_password(ei, pwd.decode("utf-8"))
        count += 1
        return
    
    for pwd[pos] in range(ord('a'), ord('z') + 1):
        _generate(pwd, pos - 1, );

count = 0
start = time.time()
ei = msoffcrypto_password_verifier.parse_ei_file("EncryptionInfo")
print "Started: " + str(start)
pwd = bytearray(8)
_generate(pwd, 7)