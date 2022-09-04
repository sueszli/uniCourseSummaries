**Name:** balint

**Points:** Not yet graded 

<hr>

SHAnty
======

Overview
--------
"shanty" asks the user for a password, and then compares the password to a saved and hashed password. Is the password correct the content of the file with the path "/challenges/shanty/info" is printed to the screen. Does the provided password (in hashed format) not match to the saved one, no information is read from the file, rather only a short info is printed to the screen with ``no`` value.

Vulnerability
-------------
The vulnerabilities lies in the ```scanf("%69s", password);``` comand and the asociated ``password array``. Since ``scanf`` is set to read 69 characters, the password array is initialized with a size of only [20] --> which leads to the overflow (if enough input is provided).

Exploitation
------------

First I ran the binary to see what the program even does, and tried it with different inputs, to see if i can get any response - since no "exploitable" response was generated continued with information gathering.
Then I inspected the given binary:
``file shanty`` = shows what type of File it is (ELF in this case) and if it was stripped or not. Which it wasn't, so some ascii readable symbols could be contained in the binary. Which is readable by the command ``strings shanty``.
Since I didn't discover any useful strings i used ``checksec shanty``, which shows what type of protection is used on the binary. There we can see that it is not possible to run commands directly from the stack (NX-enabled). But there are  ``No canary found``, which means that the stack is vulnerable against overflow.
After that I used ``ltrace ./shanty`` to see what actions are preformed by the program, and I also inspected the provided ``.c`` File. Also I used another command : ```ROPgadget --binary shanty```, this shows what the binary does on the stack, which is useful in this case.
By using ``gdb`` and stoping the program, I created a table where i noted where and in which order which variable (seen in the .c) is stored. This is used later for the payload. After this I tried different inputs and inspected the memory content after certain steps (mostly before and after the sha1 operation). There it is quickly visible that beginning with the password every vartiable is overwriteable - even the correct (stored) passwor. Besides that this hashed password is not completely overwriteable. The last 3 Bytes stay as they are.
This gives us the option to find a password, by ``bruteforcing`` which ends exactly on those 3 bytes (in Hex). For this a short python script is very handy:

```python
#!/usr/bin/env python3

import pwn
import string
import hashlib

def matchPW(s,pwHex):
    a = hashlib.sha1(s.encode()).hexdigest()

    if (a.endswith(pwHex)):
        print(a+" --- "+s)



def main():

    alph = string.ascii_letters + string.digits
    pwHex = "00c103"

    res = pwn.iters.bruteforce(
                lambda x: matchPW(x, pwHex),
                alph, 7)


    print(res)


if __name__ == '__main__':
    main()
``` 
This program above finds a sha1 encoded passwords that end with the provided suffix (here "00c103"). This program can be implemented differently aswell, since this does ``not`` stop. It just prints every possible solution and the matching ``unencrypted`` string. This is because I wanted to find a hex sequence without any 0s in it (besides the fixed bytes). Since while passing 0s as hex (for eg: \x0d) this can be interpreted as the special character \f, which leads to a differnt input than expected. But pretty quickly we can find a phrase ``dLZZY`` which exactly matches my expectations and ends with the fixed suffix.
(e7842c64b35a2d548aa96efc19d4af9b45``00c103``).

Having this Info we can now set up another python script which handles the input and provides us the solution:
```python
#!/usr/bin/env python3

from pwn import *
import array as arr
import struct
import hashlib

def main():

    elf = ELF("/challenges/shanty/shanty")
    p = elf.process()

  


    salt = "dLZZY"

    pad = ("A"*20)
    corr_hash_override_HEX = "e7842c64b35a2d548aa96efc19d4af9b4500c103"
    corr_hash_override = "\xe7\x84\x2c\x64\xb3\x5a\x2d\x54\x8a\xa9\x6e\xfc\x19\xd4\xaf\x9b\x45 "

    filename ="/challenges/shanty/flag\x00"

    inp = pad + salt+"\x00" + "AA" + filename + corr_hash_override
    print(inp)
    p.sendline(inp)

    p.interactive()



if __name__ == '__main__':
    main()
```

Now I started setting up the exploitation, by first providing all known information to the script, like the ``padding`` (which is needed, since from there the stack starts which is ``not`` expected to be overwritten). In this case it's the 20 characters that are expected to be the password. Here it doesn't matter what we fill in, since it will not be used anyways. We can also provide the path of the Info file (which is later changed to the path of the flag file). And of course the calculated "password" and the corresponding sha1 hashed sequence. I also provide this in hex representation in ``corr_hash_override``.
The communication with the binary and the python script is done by the tool of the pwn-library. Where it sets a "tube" arround the process and enables communication with it. I send, after everything is done with p.sendline the payload as an input to the process.

After this I start building the payload, which is at this point simple, since I know how the stack looks like, due to the gdb inspection.
The ``payload``, here called ``inp`` consits of the following components:
- padding
- salt + \x00
- "AA"
- filename (= path to the Info/Flag file)
- corr_hash_override

The padding is explained above...
The salt and the \x00 (null) is the first sequence we force into the memory, into an unwanted place. This contains the unencrypted password (that produces a known SHA1 when hashes), and the null-character is ``needed`` to stop the SAH1 operation at the end of the bruteforced phrase, otherwise it would not stop, and take the whole ``salted_password`` as an input (to be encrypted).That would produce an unknown output. The "AA" is only provided (and can be almost anything) to fill up the space so i can get at the Memory address which is from where the program reads the path to the file, else i would have had to find a longer unencrypted phrase that ends with the fixed suffix, which takes longer. The filename is a simple path to the file. First I tried with the ../Info, but unfortunately that does not provide any Information for solving the challenge. So i tried directly to print the content of the ../flag, since it is read-only by the user group "shaty". And our binary runs with the ``gid`` of shanty. This sequence is also null-terminated so the fopen knows where to stop reading the path.
And finally to the ``corr_hash_override``. This is the result of a sha1 operatrion on the provided unencrypted string ``dLZZY``. But I only use the first 34 chars, since the last 6 are not overwriteable and already in the memory. I represent these numbers in a hex format and then concatenate it to the payload.

So when the program processes the inputed password, it hashes the fake input ``dLZZY``, now without any salt and ignoring what as password is provided, and the output is the "faked", stored correct password, which I have overwritten (besides the last 3 bytes) and therefor matches and accepts the password. After this, I changed the path of the Info file to the Flag file, and as a result I got the Flag.

Solution
--------
```scanf("%19s", password);```
If the line with scanf is changed to this, the array ``password`` can not be overflooded by the user with a long input, sinde the scanf reads only as many chars as the array is sized ([20]). Or one could also extend the arrays size to [70], if the scanf line is keept in the original format.

Furthermore it is useful to set stack protection by for eg canaries, which is an automated process with standard compilers unless, like in this case this is manually disabled. So compiling with this flag is not optimal ```-fno-stack-protector```.
