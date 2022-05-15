#!/usr/bin/python3
from Crypto.Cipher import AES
import argparse
import random, string
import sys

def encrypt(key, shellcode):
	# Initialisation vector
	iv = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
	iv = bytes(iv, encoding='utf-8')

	# Set up AES CBC encryption scheme using key and iv
	aes = AES.new(key, AES.MODE_CBC, iv)

	# Calculate number of padding bytes needed
	l = len(shellcode)
	r = l % 16
	offset = 16 - r

	print('\n[*] Shellcode length: %d bytes (+ %d bytes padding)' % (l,offset))

	print('\n[*] Key: %s' % key)
	
	plain_sc = ''
	for i in bytearray(shellcode):
		plain_sc += '\\x%02x' % i

	print('\n[*] Plaintext Shellcode: "%s"' % plain_sc)

	# Pad shellcode with 'A' characters till size is divisible by 16
	while len(shellcode) % 16 != 0:
		shellcode = shellcode + bytes("A", encoding='utf-8')

	plain_sc = ''
	for i in bytearray(shellcode):
		plain_sc += '\\x%02x' % i
	
	# Encrypt shellcode with IV prepended
	sc = iv + aes.encrypt(plain_sc)

	encrypted = ''
	for i in bytearray(sc):
		encrypted += '\\x%02x' % i

	return encrypted

def gen_key():
	# Generate randomised 16-byte key
	key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
	return key	

def main():
	# Process arguments
	parser = argparse.ArgumentParser(description='Custom Linux x86 shellcode crypter using AES-CBC')
	parser.add_argument('-k', '--key', type=str, help='16-byte encryption key to encrypt the shellcode payload', default=gen_key())
	parser.add_argument('-p', '--payload', type=str, help='Shellcode payload to encrypt')
	args = parser.parse_args()

	if len(sys.argv) == 1:
                parser.print_help()
                sys.exit()

	# Convert string shellcode into byte array
	shellcode = args.payload	
	shellcode = shellcode.replace('\\x', '')
	shellcode = bytes.fromhex(shellcode)

	if len(args.key) % 16 != 0:
		print("[-] Key must be 16 bytes long. Exiting.")
		sys.exit(1)

	# Encrypt and print the shellcode
	encrypted = encrypt(args.key, shellcode)
	print('\n[+] Encrypted Shellcode: "%s"\n' % encrypted)

if __name__ == "__main__":
	main()
