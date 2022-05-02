#!/usr/bin/python3
import os

def update_decoder(shellcode):

	decoder_file = open("custom_decoder.nasm", "rt")
	data = decoder_file.read()
	data = data.replace("SHELLCODE", shellcode)
	
	decoder_file.close()
	decoder_file = open("tmp.nasm", "wt")
	decoder_file.write(data)
	decoder_file.close()

def set_shellcode(shellcode):

        shellcode_file = open("shellcode.c", "rt")
        data = shellcode_file.read()
        data = data.replace("SHELLCODE", shellcode)

        shellcode_file.close()
        shellcode_file = open("tmp.c", "wt")
        shellcode_file.write(data)
        shellcode_file.close()

def gen_shellcode(filename):
	stream = os.popen("""objdump -d {} |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'""".format(filename))
	shellcode = stream.read().rstrip()
	shellcode = shellcode.strip('"')
	return shellcode.strip('"')

def main():

	encoded = os.popen('python3 custom_encoder.py').read().split('\n')[1].strip()
	
	# Insert encoded execve() payload into decoder
	update_decoder(encoded)
	os.system('nasm -f elf32 -o tmp.o tmp.nasm')
	os.system('ld -o tmp tmp.o')

	# Generate custom decoder shellcode	
	shellcode = gen_shellcode('tmp')
	# Copy shellcode into shellcode.c
	set_shellcode(shellcode)
	
	# Compile C skeleton file
	os.system('gcc -fno-stack-protector -z execstack tmp.c -o custom_decoder')
	
	print("[*] Custom decoder generated. Run ./custom_decoder to execute.")
	
	# Cleanup
	os.system('rm tmp*')	

if __name__ == "__main__":
	main()
