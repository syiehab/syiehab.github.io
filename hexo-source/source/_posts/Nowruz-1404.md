---
title: Nowruz-1404
permalink: 2025/05/01/Nowruz-1404/
disableNunjucks: true
date: '2025-05-01T01:16:08.000Z'
updated: '2025-05-01T02:01:34.813Z'
tags:
  - CTF
  - Predicting Python urandom
  - RSA
categories: []
cover: /cover/nowruz.png
top_img: https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/i/d96bb958-4e6c-4ce0-9447-fbe226fbbecf/df3ce2g-46bc6c43-3baf-4388-b84a-6c49031e2f5b.jpg
---

# Nowruz 1404

Nowruz 1404 is an online jeopardy-style Capture The Flag competition organized by the FlagMotori team.  
I played this ctf under RE:UN10N team and got 10th place. This writeup will cover the crypto challenges only.

* * *

# Crypto

## Brutal RSA

**Question:**

Sometimes you need to be cruel to be able to solve a crypto challenge, don’t you? Wrap the decrypted message in: FMCTF{}

output.txt:

```plaintext
c =  41371441628678749855341069318913940139183366190092850457791401944637484881722387130432528789403867120983310612023037050412981687401539375118177921234958241549652642148049464476777138721957300380163011255302922062871368980358844918698066643476906429304993326666393192819367202508911333287188748033044647
e =  3
n =  125533848452137763185016834412259349043987425043688722410453579918645013940088212764269073831951730407180201649381111989694930753816422349270797992511026080967667823475550286796327579680655909172631694714891168782703472181155691095137469432249992072921349964218538827606766136606019411932023475455088911
```

### Solution

We are given an RSA ciphertext with a small public exponent $e = 3$, a large modulus $n$, and the ciphertext $c$. The flag is encrypted, and we are to recover the original plaintext.

Idea:  
When the public exponent e is small (e = 3), and the original message m is small such that $m^3 < n$, then the RSA encryption:

<script type="math/tex; mode=display">c = m^e\ mod\ n</script>

might actually be equal to $m^e$ (modular reduction has no effect). In this case, we can simply take the cube root of $c$ to retrieve the plaintext.

However, if $m^3 > n$, we try to find a small multiple of $n$, say $kn$, such that:

<script type="math/tex; mode=display">m^3 = c + kn</script>

We brute-force values of $k$ until $c + kn$ becomes a perfect cube.

solve.py  

```python
from gmpy2 import iroot
import itertools
from Crypto.Util.number import long_to_bytes

c =  41371441628678749855341069318913940139183366190092850457791401944637484881722387130432528789403867120983310612023037050412981687401539375118177921234958241549652642148049464476777138721957300380163011255302922062871368980358844918698066643476906429304993326666393192819367202508911333287188748033044647
e =  3
n =  125533848452137763185016834412259349043987425043688722410453579918645013940088212764269073831951730407180201649381111989694930753816422349270797992511026080967667823475550286796327579680655909172631694714891168782703472181155691095137469432249992072921349964218538827606766136606019411932023475455088911

for k in itertools.count():
    c_before_mod = c + n*k
    
    if iroot(c_before_mod, e)[1]:
        break

plaintext = long_to_bytes(iroot(c_before_mod, e)[0])
print(plaintext.decode())
```

  
Flag: `FMCTF{Bru7ef0rce_1s_s0me71mes_4n_effective_W4y!!!}`

## Circular Maze

chall.py  

```python
flag = "FMCTF{REDACTED}"


def enc(data : str):
    result = []
    for i in range(len(data)):
        result.append(((ord(data[i - 1]) + ord(data[i]) + ord(data[(i + 1) % len(data)])) % 256).to_bytes())
                
    return b''.join(result)
print(enc(flag))
open("./flag.enc", "wb").write(enc(flag))
```
