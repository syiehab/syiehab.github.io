---
title: WargamesMY 2024
permalink: 2024/12/30/wargamesMY-2024/
disableNunjucks: true
date: '2024-12-29T17:25:12.000Z'
updated: '2024-12-30T09:56:54.113Z'
tags:
  - CTF
categories:
  - Writeup
cover: /cover/wgmy24.png
top_img: https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/i/d96bb958-4e6c-4ce0-9447-fbe226fbbecf/df3ce2g-46bc6c43-3baf-4388-b84a-6c49031e2f5b.jpg
---

# WargamesMY 2024

Writeup for the challenges that I solved in Wargames.MY 2024  
This is my first time participating in WMGY and we solved some solvable challenges.

![image](https://github.com/user-attachments/assets/264db245-cd27-429b-93a7-eae98dce70a4)

* * *

# Misc

## Christmas GIFt

Here is your christmas GIFt from santa! Just open and wait for it..

### Solution

The solution is really like the description, *Just open and wait for it..*  
Opened it in stegsolve and the flag is on `frame 1402`  
![Screenshot 2024-12-30 003945](https://github.com/user-attachments/assets/e05b3b38-d993-4943-84c9-e8d7c767d3af)

## DCM Meta

“\[25, 10, 0, 3, 17, 19, 23, 27, 4, 13, 20, 8, 24, 21, 31, 15, 7, 29, 6, 1, 9, 30, 22, 5, 28, 18, 26, 11, 2, 14, 16, 12\]”

### Observation

![Screenshot 2024-12-30 004413](https://github.com/user-attachments/assets/8e2e5bab-4338-4172-aca6-829a6a61faea)

Looks like the bytes contain the flag.

### Solutions

> solved by @benkyou

Take the hex string and map according to challenge description

```python
import pydicom

# Read the DICOM file
dicom_file = "challenge.dcm"
dataset = pydicom.dcmread(dicom_file)

# Print all metadata
print(dataset)
```

parse

```plaintext
$ python3 dicom.py | awk '{print $6}' | cut -d'\' -f1 | cut -d"'" -f2 | tr '\n' ' '  f 6 3 a c d 3 b 7 8 1 2 7 c 1 d 7 d 3 e 7 0 0 b 5 5 6 6 5 3 5 4 
```

```python
s = "f 6 3 a c d 3 b 7 8 1 2 7 c 1 d 7 d 3 e 7 0 0 b 5 5 6 6 5 3 5 4"
s = s.replace(' ', '')

mapping = [25, 10, 0, 3, 17, 19, 23, 27, 4, 13, 20, 8, 24, 21, 31, 15, 7, 29, 6, 1, 9, 30, 22, 5, 28, 18, 26, 11, 2, 14, 16, \
12]

flag = ''.join([s[i] for i in mapping])
print("wgmy{" + flag + "}")
```

Flag: `wgmy{51fadeb6cc77504db336850d53623177}`

## Invisible Ink

The flag is hidden somewhere in this GIF. You can’t see it? Must be written in transparent ink.

### Solution

> solved by @benkyou

stegsolve to extract the GIF frames. You’ll get two that stand out. Apply filter to get partial flags, then layer togethre to get full flag

![image](https://github.com/user-attachments/assets/d6aa2a3b-a43c-4110-945f-1213cf76c154)

Flag: `wgmy{d41d8cd98f00b204e9800998ecf8427e}`

* * *

# Crypto

## Credentials

We found a leak of a blackmarket website’s login credentials. Can you find the password of the user osman and successfully decrypt it?

### Solution

Open the user.txt in text editor that have line number and find `osman`. Take note at the line number and find the password for the same line.

![Screenshot 2024-12-30 004748](https://github.com/user-attachments/assets/5c93f7ac-e46f-43fc-8d5b-13c890fbe80f)

Found in `line 337`

![Screenshot 2024-12-30 004924](https://github.com/user-attachments/assets/c9f30c1d-d3d0-48bc-bb0d-7ffdd06359ab)

ROT -3 and get the flag: `WGMY{b6d180d9c302d8a8daad1f2174a0b212}`

## Rick’S Algorithm

My friend Rick designed an alogrithm that is super secure! Feel free to try it!

### Observation

Challenge code:

```python
from Crypto.Util.number import *
import os
from secret import revealFlag
flag = bytes_to_long(b"wgmy{REDACTED}")

p = getStrongPrime(1024)
q = getStrongPrime(1024)
e = 0x557
n = p*q
phi = (p-1)*(q-1)
d = inverse(e,phi)

while True:
	print("Choose an option below")
	print("=======================")
	print("1. Encrypt a message")
	print("2. Decrypt a message")
	print("3. Print encrypted flag")
	print("4. Print flag")
	print("5. Exit")

	try:
		option = input("Enter option: ")
		if option == "1":
			m = bytes_to_long(input("Enter message to encrypt: ").encode())
			print(f"Encrypted message: {pow(m,e,n)}")
		elif option == "2":
			c = int(input("Enter ciphertext to decrypt: "))
			if c % pow(flag,e,n) == 0 or flag % pow(c,d,n) == 0:
				print("HACKER ALERT!!")
				break
			print(f"Decrypted message: {pow(c,d,n)}")
		elif option == "3":
			print(f"Encrypted flag: {pow(flag,e,n)}")
		elif option == "4":
			print("Revealing flag: ")
			revealFlag()
		elif option == "5":
			print("Bye!!")
			break
	except Exception as e:
		print("HACKER ALERT!!")
```

An RSA Oracle that take user input and can encrypt and decrypt the encrypted message but the flag.

```python
if c % pow(flag,e,n) == 0 or flag % pow(c,d,n) == 0:
    print("HACKER ALERT!!")
    break
```

Need to pass this condition in order to able decrypt the flag.

```python
c % pow(flag,e,n) ==  0
```

will abort if the encrypted message we provide is a multiply of encrypted flag

```python
flag % pow(c,d,n) == 0
```

will abort if the flag is a multiply of our decrypted message.

### Solution

To bypass the first condition we need to make sure our encrypted message is not a multiply of of encrypted flag. This can be done by adding $n$ to $c$ since $(c + n)^d\\ mod\\ n\\ =\\ (c)^d\\ mod\\ n$ so we will able to get $m$.

However doing this only won’t pass the second check, since our `m == flag` so `flag % m == 0`. So we need to make sure our $m$ is not equal to flag but still holding value of flag.

We can achieve this by decrypting `c*2` and divide by `2` when getting the bytes.

to get `c*2`:

<script type="math/tex; mode=display">c \cdot 2 = (m \cdot 2)^e\ mod\ n</script><script type="math/tex; mode=display">c \cdot 2 = (m)^e\ mod\ n \cdot (2)^e\ mod\ n</script>

So we need to encrypt `2` and multiply it with `encrypted flag` so we get `c*2`

Combining the solution we need to pass in $((c\\cdot2)\\ +\\ n)$ to the decrypt function and get `m * 2`.  
Then, to get `m` just `m // 2`

Solution Steps:

-   Calculate n
-   `c2 = encrypt(2)`
-   `c1 = flag_enc`
-   `c = (c1 * c2) + n`
-   `m = decrypt(c) // 2`
-   `long_to_bytes(m).decode()`

Solution script

```python
from pwn import *
from Crypto.Util.number import *
import gmpy2

r = remote("43.216.119.115",32823)
e = 0x557

def encrypt(m):
    r.recvuntil(b"option: ")
    r.sendline(b"1")
    r.recvuntil(b"encrypt: ")
    r.sendline(m)
    r.recvuntil(b"message: ")
    return int(r.recvline().strip())

def decrypt(m):
    r.recvuntil(b"option: ")
    r.sendline(b"2")
    r.recvuntil(b"decrypt: ")
    r.sendline(m)
    r.recvuntil(b"message: ")
    return int(r.recvline().strip())

def getFlag():
    r.recvuntil(b"option: ")
    r.sendline(b"3")
    r.recvuntil(b"flag: ")
    return int(r.recvline().strip())

# Get n
def recover_pubkey():
    two = encrypt(b'\x02')
    three = encrypt(b'\x03')
    power_two = encrypt(b'\x04')
    power_three = encrypt(b'\x09')
    n = gmpy2.gcd(two ** 2 - power_two, three ** 2 - power_three)
    while n % 2 == 0:
        n = n / 2
    while n % 3 == 0:
        n = n / 3
    return n

flag_enc = getFlag()

n = recover_pubkey()
c2 = encrypt(b'\x02')
c = (flag_enc * c2) + n
m2 = decrypt(str(c).encode())
m = m2 // 2
print("Retrieved m:", m)
flag = long_to_bytes(m).decode()
print("Decrypted Flag:", flag)
```

Flag: `wgmy{ce7a475ff0e122e6ac34c3765449f71d}`

* * *

# Forensics

## I Can’t Manipulate People

Partial traffic packet captured from hacked machine, can you analyze the provided pcap file to extract the message from the packet perhaps by reading the packet data?

### Observation

Every last byte in the packets got flag..

### Solution

extract all last byte in packet

```plaintext
tshark -r input.pcap -Y "icmp && data" -T fields -e data
```

Flag: `WGMY{1e3b71d57e466ab71b43c2641a4b34f4}`

## Unwanted Meow

Uh.. Oh.. Help me, I just browsing funny cats memes, when I click download cute cat picture, the file that been download seems little bit wierd. I accidently run the file making my files shredded. Ughh now I hate cat meowing at me.

### Solution

Opened in cyberchef and remove all `meow` words to fix the image

![image](https://github.com/user-attachments/assets/6002a607-6ce8-4fcc-b9c5-8a6c17c667f5)

Flag: `WGMY{4a4be40c96ac6314e91d93f38043a634}`

* * *

# Game

## World 1

Game hacking is back!  
Can you save the princess?  
White screen? That is a part of the challenge, try to overcome it.

### Solution

Edit the `.rmmzsave` file at [saveeditonline](https://www.saveeditonline.com/) to get insane stats to defeat boss easily and obtain all flag part.  
![image](https://github.com/user-attachments/assets/0fa3dc05-e5c3-4344-a304-0bc092b2161c)

Flag: `wgmy{5ce7d7a7140ebabf5cd43effd3fcaac2}`

## World 2

Welp, time to do it again.  
Unable to install? That is a part of the challenge, try to overcome it.

### Solution

Flag 1 - 4 can get by playing the game.  
Flag 5 can be found in `assets/www/img/pictures/QR Code 5A.png_`  
Download the QR file and decrypt it at [https://petschko.org/tools/mv\_decrypter/index.html](https://petschko.org/tools/mv_decrypter/index.html#en-decrypt)

Flag: `wgmy{4068a87d81d8c901043885bac4f51785}`

* * *

# Reverse

## Stones

When Thanos snapped his fingers, half of the flag was blipped. We need the Avengers to retrieve the other half.  
There’s no flag in the movie, but there is a slash flag on the server

### Observation

Opening the file in ghidra shows that it is from python

### Solution

Extract pyc using this website: [https://pyinstxtractor-web.netlify.app/](https://pyinstxtractor-web.netlify.app/)  
Decompile pyc using this website: [https://www.lddgo.net/en/string/pyc-compile-decompile](https://www.lddgo.net/en/string/pyc-compile-decompile)

decompiled python code:  

```python
import requests
from datetime import datetime
from urllib.request import urlopen
from datetime import datetime
server_url = 'http://3.142.133.106:8000/'
current_time = urlopen('http://just-the-time.appspot.com/')
current_time = current_time.read().strip()
current_time = current_time.decode('utf-8')
current_date = current_time.split(' ')[0]
local_date = datetime.now().strftime('%Y-%m-%d')
if current_date == local_date:
    print("We're gonna need a really big brain; bigger than his?")
first_flag = 'WGMY{1d2993'
user_date = current_date
params = {
    'first_flag': first_flag,
    'date': user_date }
response = requests.get(server_url, params, **('params',))
if response.status_code == 200:
    print(response.json()['flag'])
    return None
None(response.json()['error'])
```

  
We need to give the correct date in the parameter to get the flag.  
I was stuck for a while until the description mention that *“there is a slash flag on the server”*  
so by going to `http://3.142.133.106:8000/flag` gave us details

```plaintext
{"Upload Date" : "https://www.youtube.com/watch?v=V0zJb2K4Yi8&t=75s"}
```

take the upload date of the video and pass it to the date parameter and get the flag.  
![image](https://github.com/user-attachments/assets/b8f7a1f2-9ad7-4bc6-85fd-34f9816c33ed)

Final payload  

```plaintext
http://3.142.133.106:8000/?first_flag=WGMY{1d2993&date=2022-07-25
```

Flag: `didn't save T_T`

## Sudoku

Easy stuff, frfr. You dont need to brute force or guess anything.  
The final flag don’t have any dot (.)

Given output file  

```plaintext
z v7o1 an7570 9d.tl3 7.4b 7n2pws .qodx v7oc ye68u m.7r, t728{09er1bzbs9sx5sosu7719besr39zscbx}
```

  
Looks like encrypted flag

### Solutions

Decompiled using the same method as previous challenge:

```python
import random
alphabet = 'abcdelmnopqrstuvwxyz1234567890.'
plaintext = '0 t.e1 qu.c.2 brown3 .ox4 .umps5 over6 t.e7 lazy8 do.9, w.my{[REDACTED]}'

def makeKey(alphabet):
    alphabet = random(alphabet)
    join.shuffle(alphabet)
    return ''.join(alphabet)

key = makeKey(alphabet)

def encrypt(plaintext, key, alphabet):
    pass
# WARNING: Decompyle incomplete

enc = encrypt(plaintext, key, alphabet)
```

The code encrypted the plaintext by shuffling the alphabet

My observation is that the `alphabet` variable contains all letters except `fghijk` which it replaced those letters with `.`

Since we have the `plaintext` and `ciphertext` we can create a script to map the letters that it replaced to obtain the encryption key and obtain back the full flag

**Solution script:**  

```python
plaintext = '0 t.e1 qu.c.2 brown3 .ox4 .umps5 over6 t.e7 lazy8 do.9, w.my'
ciphertext_mapping = 'z v7o1 an7570 9d.tl3 7.4b 7n2pws .qodx v7oc ye68u m.7r, t728'
encoded_message = 'z v7o1 an7570 9d.tl3 7.4b 7n2pws .qodx v7oc ye68u m.7r, t728{09er1bzbs9sx5sosu7719besr39zscbx}'

# Create the mapping (ciphertext -> plaintext)
decode_map = {ciphertext_mapping[i]: plaintext[i] for i in range(len(plaintext))}

# Decode the message
decoded_message = ''.join(decode_map[char] if char in decode_map else char for char in encoded_message)

print(decoded_message)
```

  
Output: `0 t.e1 qu.c.2 brown3 .ox4 .umps5 over6 t.e7 lazy8 do.9, w.my{2ba914045b56c5e58..1b4a593b05746}`

The challenge mentioned that *“The final flag don’t have any dot (.)”* so we can just replace the dot `(.)` with letter `f` since in hexadecimal only `abcdef` is valid and the script replaced `fghijk` with `(.)`

Flag: `wgmy{2ba914045b56c5e58ff1b4a593b05746}`

![image](https://github.com/user-attachments/assets/d7cec77c-800a-4618-b9ca-eed8d471cda2)

Woohoo 1 first blood (only) xD
