---
title: ApoorvCTF
permalink: 2025/03/05/ApoorvCTF/
disableNunjucks: true
date: '2025-03-05T13:06:37.000Z'
updated: '2025-05-01T01:14:33.880Z'
tags:
  - CTF
  - AES-ECB
categories:
  - Writeup
cover: /cover/apoorvctf.png
top_img: https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/i/d96bb958-4e6c-4ce0-9447-fbe226fbbecf/df3ce2g-46bc6c43-3baf-4388-b84a-6c49031e2f5b.jpg
---

We played ApoorvCTF

* * *

# Crypto

## kowareta cipher

THe question is about AES-ECB Plaintext Recovery. It is a cryptographic attack that exploits the weaknesses of the ECB mode. In ECB mode, identical plaintext blocks are encrypted into identical ciphertext blocks, making it vulnerable to pattern recognition and chosen-plaintext attacks.

**Chall.py**  

```python
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from random import randbytes

def main():
    key = randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    flag = b'apoorvctf{fake_flag_123}'

    print("Welcome to the ECB Oracle challenge!")
    print("Enter your input in hex format.")

    try:
        while True:
            print("Enter your input: ", end="", flush=True)
            userinput = sys.stdin.readline().strip()

            if not userinput:
                break

            try:
                userinput = bytes.fromhex(userinput)
                ciphertext = cipher.encrypt(pad(userinput + flag + userinput, 16))
                print(ciphertext)
                print("Ciphertext:", ciphertext.hex())

            except Exception as e:
                print(f"Error: {str(e)}")   

    except KeyboardInterrupt:
        print("Server shutting down.")

if __name__ == "__main__":
    main()

main()
```

I’m using a script from John Hammond’s YT video [here](https://www.youtube.com/watch?v=f-iz_ZAS258&t=1572s&ab_channel=JohnHammond)

**solve.py**

```python

from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from string import printable

host = "chals1.apoorvctf.xyz"
port = 4001

p = remote(host,port)

def get_block(encrypted):
    new = []
    for i in range(0, len(encrypted), block_length):
        new.append(encrypted[i:i+block_length])
    return new

def encrypt(payload):
    p.sendline(payload)
    p.recvuntil(b'Ciphertext: ')
    blocks = p.recvline().strip().decode('utf-8')
    p.recvuntil(b': ')
    return blocks

encrypted_length = 32
block_length = 32

flag = 'apoorvctf{3cb_345y_crypt0_br34k'
start_length = 31 + 16

while True:
    payload = b"A" * (start_length - len(flag))
    testblock = encrypt(payload.hex().encode())
    blocks = get_block(testblock)
    print("expected: ", blocks[2])

    for c in printable:
        print("testing: ", c)
        inp ="A" * (start_length - len(flag)) + flag + c
        print("testing: ", inp)
        result = encrypt(inp.encode().hex().encode())
        result_block = get_block(result)
        if result_block[2] == blocks[2]:
            print("found: ", c)
            flag += c
            print(flag)
            break

    if flag.endswith('}'):
        print(f'{flag=}')
        break
 #apoorvctf{3cb_345y_crypt0_br34k}
```
