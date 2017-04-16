#!/usr/bin/env python

"""
Modified version of BruteForceAndroidPin.py by Alex Caithness @ CCL Forensics.
For pin and password protected Samsung Android phones using SHA1 hash.

Credit: pin_change.py by robberknight (http://forum.xda-developers.com/showthread.php?p=26730989).

Usage: BruteForceAndroidPinSamsung.py <SHA1 hash> <salt> <max code length (4-16)> <[t] option for alphanumeric password>

Tested on Samsung Galaxy SIII with numeric pin.

Modified by Chris Don (chrisd at cops.org)
"""



"""
Copyright (c) 2011, CCL Forensics
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the CCL Forensics nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL CCL FORENSICS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

import sys
from binascii import hexlify
import struct
import hashlib
import os.path
import binascii

__version__ = "1.0"
__description__ = "Brute forces a numeric Samsung Android pin or alphanumeric password"
__contact__ = "Chris Don"

CHAR_LIST = """ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"""


# returns bool (more to come), int (next index to increment)
def incr(current_pattern, index):
    #print(current_pattern)
    if index > len(current_pattern) - 1: raise ValueError("Index out of range")
    if index < 0 : return False, 0
    if current_pattern[index] == len(CHAR_LIST) - 1:
        current_pattern[index] = 0
        return incr(current_pattern, index - 1)
    else:
        current_pattern[index] += 1
        if index == len(current_pattern) - 1:
            return True, index
        else:
            #current_pattern[index + 1] = 0
            return True, len(current_pattern) - 1

def generate_pattern(length):
    current_pattern = [i for i in range(0,length)]
    yield current_pattern
    more_to_come = True
    index = length - 1

    while more_to_come:
        more_to_come, index = incr(current_pattern, index)
        yield current_pattern

def password_generator(max_length):
    if max_length <= 4:
        raise ValueError("max_length must be greater than 4")
    for current_length in range(4, max_length):
        for pattern in generate_pattern(current_length):
            yield "".join([CHAR_LIST[i] for i in pattern]).encode()

        
def code_generater(max_length):
    if max_length < 4:
        raise ValueError("max_length must be greater than 4")
    for current_length in range(4, max_length + 1):
        for i in range(0, pow(10, current_length)):
            number_string = str(i)
            padding_zeros = "0" * (current_length - len(number_string))
            yield (padding_zeros + number_string).encode("ascii")

"""
hash_string:    the string found in passcode.key which is a sha1 hash 
salt:           The salt as an integer
max_length:     The max length of the code in digits
"""
#Modified for Samsung SHA1 hash
def match_hash_to_code(hash_string, salt, max_length, brute_force_generator = code_generater):
    salt_string = hexlify(struct.pack(">q", salt))
    # strip leading 0s excluing the special case of the string being '00'
    if salt_string != b"00":
        salt_string = salt_string.lstrip(b"0")
    else:
        salt_string = b"0"
    
    
    for code_string in brute_force_generator(max_length):
        salted=(code_string + salt_string)
        hashbuf=str()
        i=0
        while i < 1024:
			hashbuf=hashlib.sha1(hashbuf+str(i)+salted).digest()
			i=i+1
		
        if binascii.hexlify(hashbuf).upper() == hash_string:
            return code_string.decode()


def print_usage():
    print()
    print("{0} <hash> <salt> <max code length (4-16)> <[t] option for alphanumeric password>".format(os.path.basename(sys.argv[0])))
    print()
        
def __main__():
    if len(sys.argv) < 4:
        print_usage()
        return

    hash_input_string = sys.argv[1]

    if len(hash_input_string) < 40:
        print("The hash string should contain, at least the sha-1 part of the passcode.key file.")
        print_usage()
        return
    try:
        salt = int(sys.argv[2])
    except ValueError:
        print("Salt must be an integer")
        print_usage()
        return
    try:
        max_length = int(sys.argv[3])
    except ValueError:
        print("Max length must be an integer between 4 and 16")
        print_usage()
        return
    if max_length < 4 or max_length > 16:
        print("Max length must be an integer between 4 and 16")
        print_usage()
        return

    if len(sys.argv) > 4 and sys.argv[4] == "t":
        gen = password_generator
        print "password"
    else:
        gen = code_generater
    result = match_hash_to_code(hash_input_string, salt, max_length, gen)
    print("Passcode: {0}".format(result))

if __name__ == "__main__":
    __main__()
