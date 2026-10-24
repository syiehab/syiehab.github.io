---
title: rsa-notes
tags: ["RSA", "Crypto"]
categories: [Notes]
date: 2026-10-24 13:33:26
---

# Crypto CTF field notes

A practical reference for recognizing a weakness, choosing an attack, and checking the result. Prepared 24 October 2026. All numeric examples are deliberately small or constructed for practice. Commands assume Bash in Linux/WSL and that your current directory is `crypto-ctf-handbook`, unless a block says otherwise.

The companion `index.html` works offline and includes full-text search, section filters, copy buttons, bookmarks, a BigInt RSA calculator, and a brute-force work estimator. The scripts are local helpers: Python code is run in your terminal, not executed by the HTML page.

## 0. Start here: a five-minute triage

1. Read the encryption code before trying tools. Identify the primitive, mode, padding, RNG, integer/byte conversion, and which values you control or observe.
2. Save inputs unchanged. Distinguish hex text, Base64 text, decimal integers, and raw bytes. Decode one layer at a time.
3. Write down knowns: RSA `(n,e,c)`, multiple keys, leaked bits, related messages, an oracle; AES `(mode,IV/nonce,ciphertext,tag)`; signature `(r,s,z)` pairs.
4. Try cheap structural checks first: bit lengths, GCDs, exact roots, repeated blocks, nonce reuse, small candidate spaces.
5. Verify every recovery. For RSA check `pow(m,e,n)==c`; for factors check `p*q==n`; for keys/signatures use an independent validation, not only a flag-looking string.

### Recognition table

| Clue in the challenge | First thing to try | Required extra condition |
|---|---|---|
| Many RSA moduli | Pairwise GCD | A prime was reused |
| `q = next_prime(p)` | Fermat | The gap is small enough for your iteration budget |
| `e = 3`, short message | Integer cube root, then `c+k*n` | No randomized padding; `k` is zero or small |
| Same message, several recipients | Håstad broadcast | Same exponent, correct ciphertext/key pairing, enough total modulus size |
| Same `n`, different `e` | Common modulus | Same encoded message; coprime exponents for direct recovery |
| `d` generated with few bits | Wiener, then Boneh–Durfee | Small private exponent, not merely a large public exponent |
| Known prefix / part of a prime | Coppersmith | A suitable polynomial and a genuinely small unknown |
| Decrypt endpoint leaks one bit | Parity or threshold oracle | Repeatable adaptive queries on chosen ciphertexts |
| Two messages differ by known affine rule | Franklin–Reiter | Same modulus/exponent and known relation |
| Same AES-CTR nonce/key | XOR / crib dragging | Same keystream positions |
| Repeated 16-byte ciphertext blocks | ECB investigation | Aligned equal plaintext blocks under one key |
| CBC “padding error” differs from other errors | Padding oracle | Chosen ciphertext access and reliable padding signal |
| Same ECDSA `r` | Nonce reuse check | Same signing key; handle possible nonce sign ambiguity |
| Timestamp or tiny seed | Bounded seed enumeration | Exact RNG and generation procedure reproduced |

### Encoding and arithmetic essentials

```python
from base64 import b64decode
from math import gcd

raw = bytes.fromhex("666c61677b64656d6f7d")
assert b64decode("ZmxhZ3tkZW1vfQ==", validate=True) == raw
m = int.from_bytes(raw, "big")
assert m.to_bytes((m.bit_length()+7)//8, "big") == raw
n = int("0xca1", 16)                    # 3233
assert pow(17, -1, 3120) == 2753         # modular inverse, Python >=3.8
assert pow(65, 17, n) == 2790            # efficient modular exponentiation
assert gcd(61, n) == 61
```

Leading zero bytes disappear in an integer conversion. When decoding an RSA block, preserve the modulus byte length: `k=(n.bit_length()+7)//8; block=m.to_bytes(k,'big')`. Use exact integers for roots and interval endpoints. `int(c**(1/3))` is unsafe for cryptographic integers.

## 1. RSA foundations and attack map

For ordinary two-prime RSA, `n=p*q` with distinct primes, `phi=(p-1)*(q-1)`, and `lambda=lcm(p-1,q-1)`. Choose `gcd(e,lambda)=1`, then `d=inverse(e,lambda)`. Raw encryption is `c=m**e mod n`; raw decryption is `m=c**d mod n`, with `0<=m<n`. A private exponent computed modulo `phi` also works.

The raw integer is often an **encoded block**, not directly the flag. OAEP and PKCS#1 v1.5 introduce encoding; their presence changes which attacks apply. The examples below explicitly identify raw/textbook assumptions. See [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) for RSA encodings.

Use the bundled helpers from a challenge solver:

```python
# If solve.py is in this handbook's directory:
import sys
sys.path.insert(0, "scripts")
from rsa_attacks import *
```

The first RSA survey to read for the broader taxonomy is [Boneh's RSA attack survey](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf). The practical derivations and bounded implementations here are accompanied by their own toy examples.

### RSA 01 — Known factors: finish the decryption

**Use when:** You have either factor of a semiprime modulus. Derive the other by exact division, calculate `d`, decrypt, then inspect encoding. This is the final step after most factoring attacks.

```python
from rsa_attacks import decrypt_factors, i2b
n, e, c, p = 3233, 17, 2790, 61
assert n % p == 0
q = n // p
m = decrypt_factors(n, e, c, p, q)
assert m == 65
print(i2b(m))                            # b'A'
```

**Failure clues:** Inverse does not exist → `e` is not coprime to the group exponent, or your factors/assumptions are wrong. Garbled text → inspect block length, padding, byte order, compression, and whether the plaintext is an AES key. The helper assumes two distinct primes and does not certify primality or unpad.

### RSA 02 — Shared prime / batch GCD

**Use when:** Several keys were generated with bad randomness. If `n1=p*q1` and `n2=p*q2`, then `gcd(n1,n2)=p` without any expensive factorization.

```python
from rsa_attacks import shared_factors
moduli = [101*113, 101*127, 137*139]
print(shared_factors(moduli))            # [(0, 1, 101)]
```

Recover each cofactor and use RSA 01. A GCD of 1 gives no factor; a GCD equal to the modulus may mean a duplicate key. Large collections call for product/remainder-tree batch GCD, while the supplied O(number_of_keys²) scan suits small CTF sets. Also check `gcd(c,n)`: a nonunit ciphertext can reveal a factor directly.

### RSA 03 — Fermat: close primes

**Use when:** `p` and `q` are close, especially `q=next_prime(p)` or both were derived from a common value. Write `n=a²-b²=(a-b)(a+b)` and search upward from `ceil(sqrt(n))` until `a²-n` is a square.

```python
from rsa_attacks import fermat
assert fermat(1022117, max_steps=1000) == (1009, 1013)
```

The number of steps is approximately `(p-q)²/(8*sqrt(n))` when the gap is small relative to the primes. Merely having primes with the same bit length does not make them close enough. Set a budget; a timeout does not establish that no close-prime weakness exists.

### RSA 04 — Exact low-exponent root

**Use when:** Raw RSA uses small `e` and the encoded integer satisfies `m**e<n`. No modular reduction happened, so `c=m**e` over the integers.

```python
from rsa_attacks import iroot
m, exact = iroot(74088, 3)
assert exact and m == 42
```

Small `e` alone is insufficient. A long message or randomized padding usually prevents the small-message condition. Never accept a rounded root without checking `m**e==c`.

### RSA 05 — Low exponent with a small wrap count

**Use when:** `m**e` is only a little larger than `n`. Search `c+k*n` for an exact `e`th power, starting at `k=0`.

```python
from rsa_attacks import low_exponent
assert low_exponent(10403, 3, 1267, max_k=20) == (42, 7)
# 42**3 = 1267 + 7*10403
```

If you know `m<=M`, then `k<=floor((M**e-c)/n)`. This can tell you immediately whether the search is feasible. For unrestricted messages the range is enormous; switching to brute force does not bypass RSA's hardness.

### RSA 06 — Håstad broadcast

**Use when:** The same integer message is encrypted under different, pairwise-coprime moduli with the same small exponent. Combine `c_i` with CRT into `C` modulo `N=product(n_i)`. If `m**e<N`, then `C=m**e` as an integer. Taking an exact root recovers `m`.

```python
from rsa_attacks import broadcast
ns = [101*107, 113*131, 137*149]
cs = [pow(42, 3, n) for n in ns]
assert broadcast(ns, cs, 3) == 42
```

With `e` recipients and `m<min(n_i)`, the size condition holds. Sometimes fewer suffice if `m` is small. Per-recipient randomized padding destroys the identical-message assumption. Check all pairwise GCDs first; a shared factor is easier to exploit than broadcast. Keep every ciphertext paired with its own modulus.

### RSA 07 — Common modulus

**Use when:** Two encryptions share `n` and the exact encoded message but use exponents `e1,e2`. If `gcd(e1,e2)=1`, extended GCD gives `a*e1+b*e2=1`, hence `m=c1**a*c2**b mod n`.

```python
from rsa_attacks import common_modulus
n, m = 3233, 65
c1, c2 = pow(m,17,n), pow(m,13,n)
assert common_modulus(n,17,c1,13,c2) == 65
```

Negative Bézout coefficients require modular inverses. If an inverse fails, compute `gcd(ciphertext,n)`; that can be the factor you need. When `gcd(e1,e2)=g>1`, the combination only yields `m**g mod n`; an ordinary root is justified only under an additional no-wrap bound. This differs from Franklin–Reiter, where the messages are related rather than identical.

### RSA 08 — Wiener: very small private exponent

**Use when:** `d` is unusually small and `p,q` have comparable sizes. The relation `e*d-k*phi=1` makes `k/d` closely approximate `e/n`. Enumerate continued-fraction convergents; test candidate `phi=(e*d-1)/k` by reconstructing `p,q`.

```python
from rsa_attacks import wiener
n = 1009*1013
e = pow(5, -1, 1008*1012)
assert wiener(n,e) == (5,1009,1013)
```

A classic sufficient setting is `q<p<2*q` and `d<n**0.25/3` with the conventional RSA relation modulo `phi`. Treat this as a sufficient bound, not a perfect yes/no cutoff. A large `e` is a clue only; ordinary large exponents do not guarantee small `d`.

### RSA 09 — Boneh–Durfee: somewhat larger small d

**Use when:** A small-`d` generation rule is evident and Wiener fails. Lattice methods exploit a bivariate modular equation derived from the RSA key relation. The familiar `d<n**0.292` regime assumes the usual balanced-prime setting and suitable parameters; practical lattice implementations can fail near the limit.

```bash
# Template: key.pub is the challenge's public key; requires Sage/backend support.
RsaCtfTool --publickey key.pub --attack boneh_durfee --private --timeout 300
```

Tune the lattice size and the estimated bound on `d` in a dedicated implementation if necessary. Increasing lattice size costs time and memory; it is not a guarantee. Read the [original Boneh–Durfee paper](https://crypto.stanford.edu/~dabo/pubs/abstracts/lowRSAexp.html) and the local implementation before adapting it. This workspace's `crypto-attacks/attacks/rsa/boneh_durfee.py` contains an unguarded challenge-solving block at import time; copy/guard that code in a scratch file before treating it as a library.

### RSA 10 — Known phi, p+q, or full d

**Use when:** A leak reveals `phi` or the prime sum. Since `p+q=n-phi+1`, the factors solve `x²-(p+q)x+n=0`. The discriminant must be an exact square.

```python
from rsa_attacks import factors_from_phi, factor_from_d
assert factors_from_phi(3233,3120) == (53,61)
p,q = factor_from_d(3233,17,2753)
assert p*q == 3233
```

With full `d`, write `e*d-1=2**s*t`, with odd `t`; random bases and repeated squaring can yield a nontrivial square root of 1, then `gcd(x-1,n)` factors the modulus. The helper caps its attempts. If full `d` is already known, simply decrypt first; factoring is useful for reconstructing a private-key file.

### RSA 11 — Leaked dp or dq / tiny CRT exponent

**Use when:** `dp=d mod (p-1)` is leaked. From `e*dp-1=k*(p-1)`, try `1<=k<e`, keep integral `p=(e*dp-1)/k+1`, and test divisibility of `n`. Substitute `dq` for the other prime.

```python
from rsa_attacks import factor_from_dp
p,q = factor_from_dp(3233,17,53)
assert p*q == 3233
```

Enumeration is practical for `e=65537`, but not for a random 2048-bit exponent. If `dp` itself is tiny but unknown, brute force candidate `dp` values and test `gcd(a**(e*dp)-a,n)` using modular powers; repeat bases when GCD is 1 or n. Leaked full CRT exponents and partial bits of them are different problems.

### RSA 12 — Coppersmith: known message prefix or suffix

**Use when:** A low-degree polynomial has a root small enough to recover. For an unknown `t`-byte suffix after prefix `P`, let `m=P*256**t+x`, `0<=x<256**t`, and solve `(P*256**t+x)**e-c=0 mod n`.

```python
# Run under sage -python. Import path assumes scripts is on sys.path.
from sage_examples import known_prefix
# Challenge template; replace n,e,c,P,t with real values:
# candidates = known_prefix(n,e,c,P,t)
# for m in candidates: assert pow(m,e,n)==c
```

Run `sage -python scripts/sage_examples.py` for a complete working instance. For a known suffix `S` of `s` bytes use `(x*256**s+S)**e-c`; a known prefix and suffix can be combined in one polynomial. The model must match exact byte order and unknown length.

For a monic degree-`delta` polynomial modulo all of `n`, think “root substantially below `n**(1/delta)`,” with implementation margin controlled by epsilon. `beta=1` means a root modulo the full modulus. `small_roots()` is not a general-purpose solver for arbitrary multivariate equations. Check Sage's [small_roots reference](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_modn_dense_ntl.html) for its precise bounds and parameters.

### RSA 13 — Coppersmith: partial prime bits

**Use when:** High bits of a factor are known. Model `p=p0+x`, where `p0` is the known prefix shifted back to its original position. Then `f(x)=p0+x` is zero modulo the unknown factor `p` of `n`, not necessarily modulo `n`.

```python
# Sage template, with known prefix P and t unknown low bits:
# p0 = P << t
# from sage_examples import partial_prime
# factors = partial_prime(n, p0, t, beta=0.49)
```

For a factor at least `n**beta`, a degree-`delta` polynomial has the familiar scale `X` below `n**(beta²/delta)` with margin. Balanced RSA gives roughly a quarter of the modulus bit length as a theoretical unknown-bit scale for the linear case. Work below that boundary; success depends on the actual factor lower bound and lattice parameters. `beta=0.5` is not justified for the smaller factor when it is below `sqrt(n)`; the demo uses a conservative `0.49`.

Known low bits need a different polynomial: `p=known_low+2**k*x`. Make it monic only if the leading coefficient is invertible modulo `n`. Sparse/random leaked bits and partial `d` require other constructions; do not paste the high-bit formula unchanged.

### RSA 14 — Franklin–Reiter related messages

**Use when:** Same `(n,e)`, with `m2=a*m1+b mod n` and known `a,b`. The polynomials `f(x)=x**e-c1` and `g(x)=(a*x+b)**e-c2` share the root `m1`. Their polynomial GCD usually becomes `x-m1` for a nondegenerate low-degree instance.

```python
# sage -python; full numeric example
from sage_examples import franklin_reiter
n,e,m,a,b = 1009*1013,3,123,2,5
assert franklin_reiter(n,e,pow(m,e,n),pow(a*m+b,e,n),a,b) == 123
```

Composite-modulus polynomial rings have zero divisors. A failed inverse during GCD is not always a dead end: GCD the problematic coefficient with `n`. If the polynomial GCD is not linear, inspect the relation or degeneracy. The RsaCtfTool CLI help in this checkout reverses the written relation; its implementation uses **`m2=a*m1+b`**, as the example above does.

### RSA 15 — Coppersmith short-pad attack

**Use when:** Two raw RSA messages encode the same long value with different short random pads, under the same key and small exponent. Eliminate the shared message using a resultant, recover the small pad difference, then reduce to related-message recovery.

```bash
# Template: ciphertext files must correspond to the two related encodings.
RsaCtfTool --publickey key.pub --decryptfile c1.bin,c2.bin --attack short_pad --timeout 300
```

The often-cited pad-difference scale is around `n**(1/e²)` for the classic construction. Exact encoding and practical bounds matter. This is not an attack on arbitrary OAEP padding and does not follow from “the plaintexts look similar.”

### RSA 16 — Pollard p−1, rho, ECM, and general factoring

**Pollard p−1:** Good when a factor's predecessor `p-1` divides an efficiently constructed exponent, commonly because its prime powers are small. Choose `M`, compute `a**M mod n`, then `gcd(a**M-1,n)`. If both factors' predecessors divide M, the result can be n; change the bound/base or method.

**Pollard rho:** Birthday-style collision search modulo an unknown factor. Roughly O(sqrt(p)) modular steps for the smallest prime factor `p`; useful for modest factors, not generic full-size RSA primes.

**ECM:** Best when one factor is relatively small. It seeks smooth elliptic-curve group orders modulo that factor. Different curves give different orders, unlike the fixed `p-1` in Pollard's method.

```python
from rsa_attacks import pollard_pm1, pollard_rho
p,q = pollard_pm1(257*1019, bound=100)
assert p*q == 257*1019
p,q = pollard_rho(1009*10007, max_steps=10000)
assert p*q == 1009*10007
```

```bash
RsaCtfTool --publickey key.pub --attack pollard_p_1 pollard_rho --private
RsaCtfTool --publickey key.pub --attack ecm --ecmdigits 25 --private --timeout 300
```

`--ecmdigits` estimates a factor's decimal digits, not modulus bits. For a small generic modulus consider QS or NFS tools. A generic, correctly generated 2048-bit RSA semiprime is not a realistic CTF brute-force target. Factoring databases are useful for previously known moduli, not proof of an algebraic weakness.

### RSA 17 — Prime modulus, prime powers, multiprime RSA

**Use when:** The challenge's modulus generation is nonstandard. If `n` is prime, `phi=n-1`. If `n=p**k`, `phi=p**(k-1)*(p-1)`. If it has several distinct prime factors, multiply their `(p_i-1)` values; with repetitions, use prime-power totients.

```python
# Sage: small demo only; factor() is not magic for large RSA moduli.
from sage.all import ZZ, euler_phi
n,e,m = 101**2,7,42
c = pow(m,e,n)
d = pow(e,-1,int(euler_phi(ZZ(n))))
assert pow(c,d,n) == m
```

Prime powers need extra care for messages divisible by p: exponentiation may not be invertible on nonunits, so ordinary RSA uniqueness is lost. RsaCtfTool's advertised main model is a two-prime semiprime; handle unusual moduli explicitly. `is_prime`, `is_square`, and exact nth-root checks are useful early tests.

### RSA 18 — Non-coprime exponent: multiple possible plaintexts

**Use when:** `gcd(e,phi)!=1`. There is no global private exponent inverse. Given the factorization, solve `x**e=c` modulo each prime, combine all roots with CRT, then filter using length/format and verify encryption.

```python
# sage -python; n=77, e=2 has several square roots for this ciphertext.
from sage.all import Zmod, CRT
p,q,e,c = 7,11,2,4
rp = Zmod(p)(c).nth_root(e, all=True)
rq = Zmod(q)(c).nth_root(e, all=True)
candidates = sorted({int(CRT(int(a),int(b),p,q)) for a in rp for b in rq})
assert candidates == [2,9,68,75]
```

For large e, root enumeration can itself be expensive or impossible without more structure. A failed `inverse(e,phi)` is information, not a Python bug. Repeated prime powers need lifting, not just the distinct-prime recipe above.

### RSA 19 — Raw RSA malleability / decrypt-oracle bypass

**Use when:** An oracle decrypts arbitrary raw RSA ciphertexts except the target. Choose invertible `r`, submit `c'=c*r**e mod n`, receive `m'=m*r mod n`, and recover `m=m'*inverse(r,n) mod n`.

```python
n,e,d,m,r = 3233,17,2753,65,2
c = pow(m,e,n)
modified = c*pow(r,e,n) % n
oracle_reply = pow(modified,d,n)          # replace only this with a real CTF oracle
recovered = oracle_reply*pow(r,-1,n) % n
assert recovered == m
```

Requires an oracle returning the raw multiplicatively related plaintext. A properly validated OAEP decrypt endpoint does not provide this capability just by decrypting valid ciphertexts. Avoid `r` that maps back to the blocked target.

### RSA 20 — Parity / LSB oracle

**Use when:** An oracle gives the least significant bit of the **raw decrypted integer** for chosen ciphertexts. Multiplying ciphertext by `2**e` repeatedly gives parity information about successive modular doublings. For odd n, this bisects an interval containing m.

```python
from rsa_attacks import parity_oracle
n,e,d,c = 3233,17,2753,2790
m = parity_oracle(n,e,c,lambda chosen: pow(chosen,d,n)&1)
assert m == 65
```

About `n.bit_length()` adaptive queries suffice for the basic noiseless setting. The helper uses rational intervals to avoid accumulated float errors and verifies the final ciphertext. A bit of an unpadded application string, noisy errors, or a different bit position requires a different model.

### RSA 21 — Bleichenbacher PKCS#1 v1.5 padding oracle

**Use when:** A service distinguishes whether chosen RSA decryptions have valid PKCS#1 v1.5 encryption padding. For a k-byte block, `B=2**(8*(k-2))`; valid encoded messages lie in `[2*B,3*B)`, with additional padding-format constraints.

Search multipliers s for which `c*s**e mod n` is accepted. Each positive result restricts the possible original plaintext intervals through `2*B <= m*s-r*n < 3*B`. Adaptive interval refinement eventually isolates m. A complete attack includes blinding, multiplier search and interval merging; it is not a one-line root attack.

```python
# Integration template using the existing crypto-attacks checkout:
# Run with sage -python from this handbook directory.
import sys
sys.path.insert(0, "../crypto-attacks")
from attacks.rsa.bleichenbacher import attack

def valid_v15(chosen_ciphertext):
    # Encode chosen_ciphertext to exactly k bytes; send to the challenge.
    # Return True ONLY for the observed valid-padding response.
    raise NotImplementedError("Implement the challenge-specific transport")

# recovered_encoded_integer = attack(valid_v15, n, e, c)
```

The transport is intentionally a template: framing, rate limits and the exact response predicate depend on the challenge. Plan for many queries, potentially far more than a parity oracle. A uniformly indistinguishable error response removes this particular signal. See [Bleichenbacher's original paper](https://www.iacr.org/cryptodb/data/paper.php?pubkey=1037).

### RSA 22 — Manger / leading-byte threshold oracle

**Use when:** An implementation leaks whether the raw decrypted value is below `B=2**(8*(k-1))`, often through a distinguishable leading-zero processing step. Manger's attack uses this threshold to grow and then narrow a plaintext interval.

```python
# Integration template; inspect this implementation's predicate before wiring.
import sys
sys.path.insert(0, "../crypto-attacks")
from attacks.rsa.manger import attack
# attack(threshold_oracle, n, e, c)
```

The local implementation expects True for a value below B, and assumes `2*B<n` and a target with the required leading zero. Verify the predicate before wiring another implementation. An OAEP label alone does not imply an exploitable Manger oracle. You need this specific observable implementation leak. See [Manger's original paper](https://www.iacr.org/archive/crypto2001/21390229.pdf).

### RSA 23 — CRT fault attack

**Use when:** A signature was computed correctly modulo one prime but incorrectly modulo the other. If the intended encoded message representative is M and faulty signature is s, then `gcd(s**e-M,n)` can reveal a factor. With a correct and faulty signature of the same representative, use `gcd(s_good-s_bad,n)`.

```python
from rsa_attacks import crt, fault_factor
n,e,d,M = 3233,17,2753,65
good = pow(M,d,n)
bad,_ = crt([good%61,(good+1)%53],[61,53])
assert fault_factor(n,e,M,bad) == (61,53)
```

M is the complete encoded signature representative, not necessarily the message integer or raw hash. Randomized signature padding changes what “same message” means for this comparison. An arbitrary bad signature usually yields GCD 1, not a factor.

### RSA 24 — Textbook signature forgery and weak verification

**Use when:** A signer/verifier implements raw RSA or checks an encoded block incompletely. With textbook signatures `s1**e=m1` and `s2**e=m2`, the product `s1*s2 mod n` verifies for `m1*m2 mod n`. Choosing an arbitrary s also defines a valid raw message `m=s**e mod n`, although it may not be a useful target message.

```python
n,e,d = 3233,17,2753
s1,s2 = pow(2,d,n),pow(3,d,n)
assert pow(s1*s2%n,e,n) == 6
```

For small-e PKCS#1 signature forgeries, an overly permissive parser that accepts a prefix while ignoring trailing data can permit carefully constructed roots. This requires a vulnerable verifier; strict PKCS#1 encoding validation or PSS prevents that shortcut. Inspect exactly what bytes the verifier checks before selecting an exploit.

### RSA 25 — Message dictionary, weak seeds and special-form primes

**Use when:** Raw deterministic RSA protects a tiny plaintext domain, such as a four-digit PIN. Encrypt each candidate under the public key and compare with c. Factoring is unnecessary.

```python
from crypto_recipes import rsa_dictionary
assert list(rsa_dictionary(3233,17,2790,[b"B",b"A"])) == [b"A"]
```

For timestamp-derived primes, reproduce the actual RNG seed, byte generation, primality search, and rejected draws. Guessing a seed without reproducing the consumption order fails. Special-form primes may expose algebraic factors or searchable parameters; model the exact formula. ROCA has a specific key-generation fingerprint and dedicated attacks; “unusual prime” is not enough to identify it.

## 2. SageMath quick syntax sheet

SageMath supplies exact arithmetic, finite fields, polynomials, matrices, lattices, and elliptic curves. Use Python for bytes, parsing and network I/O; use Sage for algebra. Examples below use ordinary Python syntax unless labeled `.sage`.

### Running code and choosing syntax

```bash
sage                                  # interactive Sage shell
sage solve.sage                        # Sage preparser enabled
sage -python solve.py                  # Python syntax, Sage libraries available
sage -python scripts/sage_examples.py  # bundled worked demos
sage -c 'print(factor(3233))'           # quick calculation
```

```python
# .py: no preparser. This style also works in Sage.
from sage.all import *
R = PolynomialRing(Zmod(3233), "x")
x = R.gen()
f = x**3 + 2*x + 1
```

```sage
# .sage / interactive Sage only:
R.<x> = PolynomialRing(Zmod(3233))
f = x^3 + 2*x + 1
```

**Critical trap:** `^` is XOR in Python but exponentiation in preparsed Sage. Prefer `**` for powers in portable code. To XOR Sage integers portably, use `operator.xor(int(a),int(b))`. Sage also turns integer literals into exact Sage integers; in ordinary Python use `QQ(1)/3` for an exact rational rather than `1/3`.

### Number types and conversion

| Object | Meaning | Example |
|---|---|---|
| `ZZ` | Arbitrary-precision integers | `ZZ("deadbeef",16)` |
| `QQ` | Exact rational numbers | `QQ(2)/3` |
| `RR` / `RealField(200)` | Approximate reals | `RealField(200)(2).sqrt()` |
| `Zmod(n)` / `Integers(n)` | Integers modulo n | `Zmod(15)(17)` gives 2 |
| `GF(p)` | Prime finite field | `GF(101)(7)` |
| `GF(2**8,name='a')` | Extension field, 256 elements | Arithmetic differs from `Zmod(256)` |
| `int(x)` | Python integer | For `to_bytes`, JSON and sockets |
| `parent(x)` | Algebraic domain of x | Useful for coercion errors |

```python
from sage.all import *
raw = b"flag{demo}"
m = ZZ(int.from_bytes(raw,"big"))
assert int(m).to_bytes((int(m).bit_length()+7)//8,"big") == raw
print(m.nbits(), m.digits(16))           # digits() is least-significant first
print(hex(int(m)), m.str(2))            # conventional display order
```

### Modular arithmetic and CRT

```python
from sage.all import *
assert gcd(12,18) == 6
g,a,b = xgcd(17,13)
assert a*17+b*13 == g == 1
assert inverse_mod(17,3120) == 2753
assert power_mod(65,17,3233) == 2790
assert CRT([2,3,2],[3,5,7]) == 23
assert Mod(5,101).multiplicative_order() == 25
assert Mod(5,101)**25 == 1
```

An inverse exists iff the GCD is 1. Over `Zmod(composite)`, not every nonzero element is invertible. CRT can also support compatible non-coprime congruences in Sage, but the bundled Python helper deliberately requires pairwise-coprime moduli.

### Primes, factors and exact roots

```python
from sage.all import *
assert is_prime(101)
assert next_prime(100) == 101
assert factor(3233) == factor(53*61)
assert euler_phi(3233) == 3120
assert ZZ(81).is_square()
assert ZZ(81).isqrt() == 9
r,exact = ZZ(74088).nth_root(3,truncate_mode=True)
assert (r,exact) == (42,True)
print(list(continued_fraction(QQ(17)/3233).convergents()))
```

`factor(n)` may be slow on large semiprimes. `nth_root(k)` without truncation may raise an exception if the number is not a perfect power. Approximate real roots are not substitutes for integer checks.

### Polynomial rings, coefficients and roots

```python
from sage.all import *
R = PolynomialRing(QQ,"x")
x = R.gen()
f = x**3-6*x**2+11*x-6
assert f(2) == 0
print(f.factor())                       # (x-3)*(x-2)*(x-1)
print(f.roots())                        # [(root,multiplicity), ...]
print(f.list())                         # [-6,11,-6,1], low degree first
assert f[0] == -6 and f.degree() == 3
print(f.derivative(), f.monic())
q,r = f.quo_rem(x-1)
assert r == 0

S = PolynomialRing(GF(101),"y")
y = S.gen()
assert set((y**2-4).roots(multiplicities=False)) == {S.base_ring()(2), S.base_ring()(99)}
```

Symbolic `var('x')` expressions and polynomial-ring generators are different objects. For `.small_roots()`, `.resultant()` and algebraic attacks, construct the correct polynomial ring. `.roots()` is ordinary root-finding in a specified domain; `.small_roots()` is a bounded modular lattice method.

### Small roots: the essential pattern

```python
# Template, not a complete challenge instance:
from sage.all import *
# R = PolynomialRing(Zmod(n),"x",implementation="NTL")
# x = R.gen()
# f = (known_prefix*256**unknown_bytes+x)**e-c
# roots = f.monic().small_roots(X=256**unknown_bytes,beta=1,epsilon=0.03)
# for r in roots:
#     candidate = known_prefix*256**unknown_bytes+int(r)
#     assert pow(candidate,e,n) == c
```

`X` bounds the unknown integer; it is not the number of bytes. `beta` describes the size of the factor on which the root holds; it is not a “success probability.” Smaller epsilon can build larger lattices and cost more. If no roots appear, check the equation, variable bounds, monicity and factor assumptions before tuning blindly.

### Multivariate polynomials and resultants

```python
from sage.all import *
R = PolynomialRing(QQ,names=("x","y"))
x,y = R.gens()
f,g = x+y-3, x-y-1
print(f.resultant(g,y))                 # eliminates y
print(R.ideal([f,g]).groebner_basis())
assert f(x=2,y=1) == g(x=2,y=1) == 0
```

A resultant can create extraneous roots or lose information in special cases; substitute candidate solutions into the original equations. Gröbner basis computation can grow rapidly. Changing from a field to a composite ring changes what operations are supported.

### Matrices, linear systems and kernels

```python
from sage.all import *
A = matrix(GF(101),[[2,3],[5,7]])
b = vector(GF(101),[11,13])
x = A.solve_right(b)                    # A*x = b
assert A*x == b
print(A.rank(), A.det(), A.inverse())
B = matrix(GF(2),[[1,0,1],[0,1,1]])
K = B.right_kernel().basis_matrix()
assert B*K.transpose() == zero_matrix(GF(2),2,K.nrows())
```

Use `GF(2)` for linear equations over bits, `GF(p)` for prime-modulus systems and `QQ` for exact rational algebra. Linear algebra over `Zmod(n)` with composite n is not automatically field linear algebra. Keep the distinction between row vectors, column multiplication, and left/right kernels explicit.

### Lattices and LLL

```python
from sage.all import *
B = matrix(ZZ,[[1,1,1],[-1,0,2],[3,5,6]])
L = B.LLL()                            # reduced ROW basis
assert abs(B.det()) == abs(L.det())
```

LLL returns short lattice vectors; it does not know what your secret is. Define the embedding, scale columns according to unknown bounds, decode candidate vectors and verify against the challenge equations. Do not apply LLL to a finite-field matrix when the attack requires an integer lattice.

### Discrete logarithms and elliptic curves

```python
from sage.all import *
g = GF(101)(2)
h = g**37
x = discrete_log(h,g,ord=g.multiplicative_order())
assert g**x == h
E = EllipticCurve(GF(97),[2,3])          # y² = x³+2x+3
P = E(3,6)
Q = 3*P
k = discrete_log(Q,P,ord=P.order(),operation='+')
assert k*P == Q
print(E.order(), P.order(), E(0))        # E(0) is the point at infinity
```

Smooth group order suggests Pohlig–Hellman; small subgroups suggest subgroup attacks if membership is not checked. Generic discrete logs in large prime-order groups remain hard. For anomalous curves, singular curves, or low embedding degree, identify the exact structural property before selecting Smart, singular-curve, or MOV attacks.

### Help and common error translations

| Error / symptom | Likely cause | Fix |
|---|---|---|
| `SyntaxError` at `R.<x>` | Running Sage syntax with Python | Use `sage file.sage` or explicit ring construction |
| `ModuleNotFoundError: sage` | Wrong interpreter | Use `sage -python file.py` |
| `Integer has no to_bytes` in some versions | Sage/Python type mismatch | `int(x).to_bytes(...)` |
| Inverse does not exist | Nonunit element | Compute GCD; it may leak a factor |
| No `.small_roots()` | Wrong parent/backend | Univariate NTL ring over `Zmod(n)` |
| Floats / precision loss | Python `/` or real roots | Use `//`, `QQ`, exact roots |
| Empty root list | Model/bound/domain mismatch | Verify polynomial and actual unknown size |
| Incorrect XOR | Sage preparser changed `^` | `operator.xor(int(a),int(b))` |

Use `help(object)` in either interpreter; in the Sage shell, `object?` shows documentation and `object??` can show source. Sage's [tutorial index](https://doc.sagemath.org/html/en/tutorial/index.html) links arithmetic, polynomials and linear algebra chapters.

## 3. Reusable crypto attack recipes

`scripts/rsa_attacks.py` and `scripts/crypto_recipes.py` use the Python standard library. `scripts/sage_examples.py` requires Sage. Import them into `solve.py` or use the small command-line interfaces. These are transparent building blocks, not an automatic universal solver.

### Recipe 01 — Single-byte XOR brute force

**When:** One unknown byte was XORed with every plaintext byte. There are only 256 keys. Rank candidates by readable text and inspect the top results.

```bash
python3 scripts/crypto_recipes.py xor 232e272724 --top 8
```

```python
from crypto_recipes import single_byte_xor, repeating_xor
c = repeating_xor(b"the secret message is here", b"K")
for score,key,plain in single_byte_xor(c):
    print(hex(key),score,plain)
```

The CLI example contains `hello` encrypted with key `0x4b`. Very short messages can rank poorly. For a flag prefix, use an exact crib check instead of relying exclusively on English scoring. All 256 keys can be shown with `--top 256`.

### Recipe 02 — Repeating-key XOR

**When:** `c[i]=p[i] XOR key[i % key_length]`. For each hypothesized length, split into columns and apply single-byte XOR scoring to each column.

```python
from crypto_recipes import repeating_xor_known_length
# Template: c is bytes, key_length is a candidate length.
# key,plain = repeating_xor_known_length(c,key_length)
```

Estimate length using normalized Hamming distances across several block pairs, then compare several candidate lengths (multiples are common false positives). A short ciphertext or binary plaintext needs stronger constraints. With a known plaintext span, directly recover the corresponding key bytes and check whether the period is consistent.

### Recipe 03 — Bounded hash brute force

**When:** You know the hash construction and the unknown input has a small search space. This helper tries all exact-length strings over an alphabet, preserves leading zeros, and supports `hash(prefix+candidate+suffix)`.

```bash
# SHA-256("1234"); should print b'1234'.
python3 scripts/crypto_recipes.py hash 03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4 --length 4
```

```python
import hashlib
from crypto_recipes import hash_search
target = hashlib.sha256(b"salt:0042!").hexdigest()
assert hash_search(target,length=4,prefix=b"salt:",suffix=b"!") == b"0042"
```

The default budget is 1,000,000 candidates; raise it explicitly with `--max-candidates` after estimating work. Search size for exact length L and alphabet size A is `A**L`; lengths 1 through L cost `sum(A**i for i in range(1,L+1))`. At measured rate R, worst-case time is candidates/R; half that is an average only if exactly one uniformly positioned solution exists.

Hashing text `"1234"` differs from hashing integer 1234 encoded in two bytes, and hex text differs from decoded bytes. For PBKDF2, scrypt or Argon2, reproduce the actual KDF, salt and parameters; this fast-hash script is not a substitute. A 128-bit random AES key is not a viable brute-force exercise.

### Recipe 04 — Dictionary attack on raw RSA

```python
from crypto_recipes import rsa_dictionary
# Template; wordlist opened as bytes preserves the candidate encoding.
# with open("words.txt","rb") as words:
#     for match in rsa_dictionary(n,e,c,words): print(match)
```

The helper removes only CR/LF line endings. It does not automatically add `flag{}`, whitespace or a terminator. Recreate those explicitly if the challenge does. This works against deterministic encryption of a small domain; randomized encoding changes the comparison.

### Recipe 05 — Reused OTP / CTR keystream and crib dragging

**When:** Two ciphertexts share keystream bytes K: `C1=P1 XOR K`, `C2=P2 XOR K`. Then `C1 XOR C2=P1 XOR P2`. A known P1 span directly reveals the corresponding P2 span.

```python
from crypto_recipes import xor_bytes, crib_drag
P1,P2,K = b"flag{one}",b"text{two}",b"123456789"
C1,C2 = xor_bytes(P1,K),xor_bytes(P2,K)
for offset,guess in crib_drag(C1,C2,b"flag{"):
    print(offset,guess)                  # offset 0 gives b'text{'
```

Check nonce, key, initial counter, and byte offset alignment. Same nonce with different keys does not imply the same keystream. Recovering one span does not automatically reveal all bytes. With many English plaintexts under one stream, combine cross-message consistency and language scoring.

### Recipe 06 — CTR and CBC bit flipping

**CTR:** A known plaintext span can be changed without knowing the key: `C'=C XOR old XOR new` at the matching offset.

```python
from crypto_recipes import ctr_patch, xor_bytes
plain,key = b"admin=0",b"1234567"
c = xor_bytes(plain,key)
modified = ctr_patch(c,6,b"0",b"1")
assert xor_bytes(modified,key) == b"admin=1"
```

**CBC:** `P_i=D(C_i) XOR C_(i-1)`. Change the previous ciphertext block by `old XOR new` to make the desired same-position change in P_i. This also corrupts P_(i-1). For the first block, change the IV and avoid that preceding-plaintext corruption. Locate exact block/byte offsets first. A verified authentication tag normally rejects either modification.

### Recipe 07 — ECB detection and byte-at-a-time recovery

```bash
# Input must be decoded binary ciphertext.
python3 scripts/crypto_recipes.py ecb ciphertext.bin --block-size 16
```

Repeated aligned ciphertext blocks suggest ECB, but do not prove it in isolation; short messages can also hide ECB repetition. For an oracle `AES-ECB(key,controlled_input || secret)`, pad your input so the next unknown byte is at a block end, build a 256-entry encrypted candidate dictionary, match the target block, and repeat. Confirm block size and determinism first. A fixed unknown prefix requires alignment; a fresh random prefix needs a more careful synchronization strategy.

### Recipe 08 — CBC padding-oracle workflow

**When:** A decrypting service exposes whether a modified CBC plaintext has valid PKCS#7 padding. Recover intermediate bytes `I=D_K(C_i)` from right to left by altering the previous block to force `01`, then `02 02`, and so on. Finally `P_i=I XOR C_(i-1)`.

The basic worst-case search is about 256 guesses per byte, plus verification queries. Last-byte successes can be false positives from an existing longer padding suffix; perturb another byte to distinguish them. Keep the IV and ciphertext framing intact, and distinguish padding validity from later parse errors.

The existing `crypto-attacks/attacks/cbc/padding_oracle.py` is an implementation reference. Inspect its function signature and test fixture before connecting a transport; API layouts differ. A useful adapter contract is `oracle(iv: bytes,ciphertext: bytes)->bool`. A timeout is not evidence of invalid padding unless the challenge establishes that behavior.

### Recipe 09 — LCG recovery

**When:** You see consecutive full states of `x_(i+1)=(a*x_i+b) mod M`. With known M and an invertible state difference, solve a and b directly, then predict the next output.

```python
from crypto_recipes import lcg_known_modulus, lcg_modulus_multiple
states = [7]
for _ in range(8): states.append((17*states[-1]+43)%101)
a,b,next_value = lcg_known_modulus(states,101)
assert (a,b) == (17,43)
multiple = lcg_modulus_multiple(states)
assert multiple > 0 and multiple % 101 == 0
```

For unknown M, let differences be `t_i=x_(i+1)-x_i`. Each `t_(i+2)*t_i-t_(i+1)**2` is a multiple of M. Their GCD may be a **multiple** of the true modulus, not the modulus itself; factor candidates and verify all observed transitions. Truncated outputs, skipped states or noninvertible differences require other methods.

### Recipe 10 — Timestamp / weak RNG seed search

```python
# Toy construction. Reproduce the challenge's exact generator calls in practice.
import random
observed = random.Random(1700000000).getrandbits(32)
hits = []
for seed in range(1699999940,1700000061):
    rng = random.Random(seed)
    if rng.getrandbits(32) == observed:
        hits.append((seed,rng.getrandbits(32)))
print(hits)                             # seed and predicted next output
```

Use a justified time window and verify another output. Python `random` is not interchangeable with C `rand`, NumPy generators, or `secrets`. Recovering a Mersenne Twister state from full outputs is another route, but byte/bit packing and hidden draws matter. Never claim that one short output uniquely identifies a seed without checking collisions.

### Recipe 11 — ECDSA nonce reuse

**When:** Two signatures use the same private key d and the same nonce k. With group order q, `s=k^-1*(z+r*d) mod q`, so `k=(z1-z2)/(s1-s2) mod q`, then `d=(s1*k-z1)/r mod q`.

```python
from crypto_recipes import ecdsa_reused_nonce
q,r,d,k,z1,z2 = 101,9,42,17,20,30
s1 = (z1+r*d)*pow(k,-1,q)%q
s2 = (z2+r*d)*pow(k,-1,q)%q
assert ecdsa_reused_nonce(q,r,s1,z1,s2,z2) == (k,d)
```

This toy tests the scalar algebra; a real recovery must verify `d*G` equals the public key and both signatures verify. The modulus is the subgroup order q, not the curve coordinate-field prime. Form z using the signature scheme's specified hash truncation. Equal r can also arise from k and −k; low-s normalization can flip signs, so try the relevant `s` / `q-s` combinations and verify.

### Recipe 12 — Other patterns worth recognizing

| Pattern | Why it matters | Practical starting point |
|---|---|---|
| Secret-prefix `hash(key || msg)` MAC | Some Merkle–Damgård hashes allow length extension | Need digest, guessed key length and exact glue padding; not HMAC |
| GCM nonce reuse | Repeats CTR stream and creates equations in GHASH key | Keep AAD, lengths and tags; tag forgery requires more than XOR alone |
| Smooth discrete-log group order | Break log into small prime-power subproblems | Factor group order, use Pohlig–Hellman, recombine with CRT |
| Unvalidated small-order public point | Leaks secret scalar residues | Need an observable key-dependent response; combine residues |
| Biased/partial ECDSA nonces | Hidden-number lattice problem | Collect sufficient independent signatures and correct bit bounds |
| Double encryption with small key domains | Meet in the middle | Store `E_k1(P)`, match against `D_k2(C)`; verify another pair |
| Low-density subset sum | Integer lattice embedding | Scale carefully, LLL, then check binary subset coefficients |
| Linear LFSR output | Linear recurrence can be reconstructed | Consecutive bits, Berlekamp–Massey or GF(2) equations |

These are recognition notes, not claims that every instance is solvable. The local [crypto-attacks implementation collection](https://github.com/jvdsn/crypto-attacks) includes many corresponding modules and tests. Read each attack's prerequisites; advanced scripts are not interchangeable CLI commands.

## 4. RsaCtfTool practical command guide

This guide targets the local checkout at `../RsaCtfTool`, commit **e1d8644e80aa48d08aa8e06d24c37cf81f3fb437**. The CLI option names, relation direction and bit layout were checked against its source, not inferred from old writeups. The [upstream project](https://github.com/RsaCtfTool/RsaCtfTool) provides general installation and usage information. Your own `--help` is authoritative after an upgrade.

**Version traps:** This version uses `--decrypt` and `--decryptfile`. Older writeups may say `--uncipher` / `--uncipherfile` or invoke `RsaCtfTool.py`. This checkout installs `RsaCtfTool` and `rsacrack`, and supports `python -m RsaCtfTool`.

### Install / launch in this workspace

```bash
# From the handbook directory; use your existing environment if already set up.
cd ../RsaCtfTool
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
RsaCtfTool --help
cd ../crypto-ctf-handbook
```

Sage is separate from a normal Python pip environment. Install it using the [SageMath installation guide](https://doc.sagemath.org/html/en/installation/index.html) appropriate to your OS. On Windows, WSL is a useful place to run the Linux commands shown here. Being able to invoke `sage` and being able to `import sage.all` from an arbitrary Python virtualenv are different capabilities.

```bash
sage --version
sage -python -c 'from sage.all import ZZ; print(ZZ(81).isqrt())'

# Alternative if your Sage Python already has RsaCtfTool's dependencies:
PYTHONPATH=../RsaCtfTool/src sage -python -m RsaCtfTool --help
```

The second command form was available in this workspace during preparation. Replace `RsaCtfTool` in later examples with that form if you do not have the console executable on PATH. Do not blindly mix pip packages between Python and Sage environments.

### Self-contained toy example

The toy values below exercise direct decryption without external files. The supplied RsaCtfTool checkout also includes many attack-specific fixtures under `../RsaCtfTool/examples/`; inspect a fixture before assuming which attack it demonstrates.

```bash
# n=3233, p=61, q=53, e=17; raw ciphertext 2790 decrypts to integer 65 ('A').
RsaCtfTool -n 3233 -p 61 -q 53 -e 17 --decrypt 2790 --private
```

This is textbook RSA with tiny values, not a secure padding example. Use Python's standard-library helpers in `scripts/rsa_attacks.py --demo` to reproduce the arithmetic without installing RsaCtfTool dependencies.

Generate additional local fixtures for close-prime, Wiener, broadcast and related-message attacks with `sage -python scripts/make_rsa_lab.py`. The script requires PyCryptodome in the interpreter that runs it and writes only to `crypto-ctf-handbook/lab/`.

### Typical workflow for a new challenge

```bash
# A. Inspect the provided key.
RsaCtfTool --dumpkey --key key.pub

# B. Choose attacks that match your clues.
RsaCtfTool --publickey key.pub --attack fermat wiener --private --timeout 60

# C. Include ciphertext so successful recovery also decrypts it.
RsaCtfTool --publickey key.pub --decryptfile cipher.bin --attack fermat --private

# D. Broader attempt if no clue dominates; some attacks may contact external services.
RsaCtfTool --publickey key.pub --attack all --private --decryptfile cipher.bin --timeout 120

# E. Inspect a recovered key or decrypt with an existing complete private key.
RsaCtfTool --dumpkey --ext --key recovered.pem
RsaCtfTool --key recovered.pem --decryptfile cipher.bin
```

`--timeout` is an attack-level setting; it is not a guaranteed overall deadline for the full queue or all external subprocesses. Missing backend messages describe unavailable attacks, not evidence that the mathematical attack failed. `--private` asks to display a recovered key; message-only attacks such as broadcast can succeed without one.

### Integer input, byte files and public-key creation

```bash
RsaCtfTool -n 3233 -e 17 --decrypt 2790 --attack fermat
RsaCtfTool -n 0xca1 -e 0x11 --decrypt 0xae6 --attack fermat
RsaCtfTool --createpub -n 3233 -e 17 > toy.pub
RsaCtfTool --dumpkey --key toy.pub
```

Use decimal or lowercase `0x`-prefixed hexadecimal for the least ambiguous numeric parsing. `--decrypt 2790` means an integer. `--decryptfile cipher.txt` does **not** mean “parse the decimal number in this text file.” It reads bytes and may auto-decode canonical Base64. Arbitrary raw bytes that also look like Base64 can therefore be ambiguous; numeric `--decrypt` avoids that issue.

```python
from pathlib import Path
n,c = 3233,2790
Path("cipher.bin").write_bytes(c.to_bytes((n.bit_length()+7)//8,"big"))
# Hex text -> raw bytes:
# Path("cipher.bin").write_bytes(bytes.fromhex(Path("cipher.hex").read_text().strip()))
```

### Multiple-key commands and ordered pairing

```bash
# GCD scanning does not require ciphertext pairing.
RsaCtfTool --publickey 'keys/*.pub' --attack common_factors --private

# Same modulus, different exponents, same message.
RsaCtfTool --publickey key_e1.pub,key_e2.pub --decryptfile c1.bin,c2.bin --attack common_modulus_related_message

# Same-n mode can also take comma-separated exponents and ciphers.
RsaCtfTool -n 3233 -e 17,13 --decrypt 2790,1666 --attack common_modulus_related_message
```

Quote wildcards so the tool receives a single pattern argument. For broadcast or paired ciphertext attacks, prefer explicit comma-separated paths: filesystem glob order is not a reliable pairing contract. The `common_modulus_related_message` attack name in this version refers to the shared-message/common-modulus case; it is separate from `franklin_reiter`.

### Leaks and Coppersmith command templates

```bash
# Full dp or dq leak (choose the appropriate parameter).
RsaCtfTool -n 3233 -e 17 --dp 53 --attack dp_leak --private --decrypt 2790
RsaCtfTool -n 3233 -e 17 --dq 49 --attack dp_leak --private --decrypt 2790

# Known prefix, four unknown BYTES; key and cipher supplied by the challenge.
RsaCtfTool --publickey key.pub --decryptfile cipher.bin --attack stereotyped_message --sm-prefix 'flag{' --sm-len 4

# Known prefix and suffix, four unknown bytes between them.
RsaCtfTool --publickey key.pub --decryptfile cipher.bin --attack stereotyped_message --sm-prefix 'flag{' --sm-suffix '}' --sm-len 4

# Hex-encoded prefix bytes; 0x666c61677b means ASCII flag{.
RsaCtfTool --publickey key.pub --decryptfile cipher.bin --attack stereotyped_message --sm-prefix 0x666c61677b --sm-len 4

# Partial p: high value is ALREADY shifted; this example means p=0x12340000+x.
# Template only: replace n's key and the prefix with the challenge data.
RsaCtfTool --publickey key.pub --attack partial_p --p-high 0x12340000 --p-unknown-bits 16 --private

# Partial private-key structures: require correctly encoded partial key material.
RsaCtfTool --key partial.pem --partial --attack partial_d --d-known-bits 20 --private
RsaCtfTool --key partial.pem --partial --attack lattice --private
```

`--sm-len` counts **bytes**; `--p-unknown-bits` and `--d-known-bits` count **bits**. Supplying 16 for the first asks for 128 unknown bits. The partial-private-key modes do not turn arbitrary fragments of PEM text into recoverable keys; inspect the implementation's expected fields. An attack name being accepted does not mean your inputs satisfy its prerequisites.

### Database, diagnostics and output

```bash
# Online lookup of a public modulus; requires network access.
RsaCtfTool --publickey key.pub --attack factordb --private

# Explicit opt-in to submitting recovered factors to the external database.
RsaCtfTool --publickey key.pub --attack fermat --private --sendtofdb

# Fingerprint checks and format conversion.
RsaCtfTool --isroca --publickey key.pub
RsaCtfTool --isconspicuous --key recovered.pem
RsaCtfTool --convert_idrsa_pub --publickey id_rsa.pub

# Diagnostics and file output.
RsaCtfTool --publickey key.pub --attack fermat --verbosity DEBUG --withtraceback --private
RsaCtfTool --publickey key.pub --attack fermat --private --output recovered.pem
```

This version appends to `--output`. Use a fresh path and one intended output type per run: multiple keys and decrypted bytes may otherwise be mixed in the same file. Do not assume logs constitute a clean PEM; verify with a key parser. `--sendtofdb` is a submission action, while `--attack factordb` is a lookup. No external submissions are needed for this handbook's lab.

### Complete CLI flag reference for the checked checkout

The examples in this table are argument fragments to append to `RsaCtfTool`; combine input flags with an appropriate action as shown in the complete commands above. `key.pub`, `cipher.bin`, `partial.pem` and `recovered.pem` are challenge placeholders, not bundled files unless explicitly under `lab/`.

| Flag | Purpose / units | Example fragment |
|---|---|---|
| `-h`, `--help` | Show parser options and available attacks | `--help` |
| `--publickey` | Public PEM path, quoted glob, or comma-separated paths | `--publickey 'keys/*.pub'` |
| `--key` | Load key for dump/private/partial operations | `--key recovered.pem --dumpkey` |
| `--password` | Passphrase for an encrypted private key | `--key protected.pem --password 'ctf-demo' --dumpkey` |
| `-n` | Modulus integer | `-n 3233` |
| `-e` | Public exponent or comma-separated exponents | `-e 17,13` |
| `-p` | Known prime factor | `-p 61` |
| `-q` | Other known factor | `-q 53` |
| `-d` | Known full private exponent | `-n 3233 -e 17 -d 2753 --private` |
| `--decrypt` | Numeric ciphertext(s), comma-separated | `--decrypt 2790` |
| `--decryptfile` | Ciphertext file(s), comma-separated | `--decryptfile c1.bin,c2.bin` |
| `--private` | Display recovered private key | `--private` |
| `--output` | Append selected result data to path | `--output recovered.pem` |
| `--attack` | One or more names, or `all` | `--attack fermat wiener` |
| `--timeout` | Per-attack seconds, default 60 | `--timeout 300` |
| `--verbosity` | DEBUG, INFO, WARNING, ERROR, CRITICAL | `--verbosity DEBUG` |
| `--withtraceback` | Include traceback diagnostics | `--withtraceback` |
| `--createpub` | Print public PEM from n and e | `--createpub -n 3233 -e 17` |
| `--dumpkey` | Display key parameters | `--dumpkey --key key.pub` |
| `--ext` | Additional CRT values in private-key dump | `--dumpkey --ext --key recovered.pem` |
| `--show_modulus` | Display n supplied numerically | `-n 3233 -e 17 --show_modulus --attack fermat` |
| `--check_publickey` | Run modulus well-formedness check before attacks | `--publickey key.pub --check_publickey --attack fermat` |
| `--isroca` | ROCA fingerprint | `--isroca --publickey key.pub` |
| `--isconspicuous` | Inspect a complete private key for suspicious structure | `--isconspicuous --key recovered.pem` |
| `--convert_idrsa_pub` | Print PEM from OpenSSH public format | `--convert_idrsa_pub --publickey id_rsa.pub` |
| `--ecmdigits` | Estimated decimal digits of a factor for ECM | `--attack ecm --ecmdigits 25` |
| `--fr-a` | Affine multiplier in implementation's `m2=a*m1+b` | `--attack franklin_reiter --fr-a 2 --fr-b 5` |
| `--fr-b` | Affine offset; this implementation rejects zero | `--fr-a 2 --fr-b 5` |
| `--sm-prefix` | Known bytes: text or `0x` hex | `--sm-prefix 'flag{'` |
| `--sm-suffix` | Known suffix bytes | `--sm-suffix '}'` |
| `--sm-len` | Number of unknown bytes | `--sm-len 4` |
| `--p-high` | Known high factor bits with low unknown bits zeroed | `--p-high 0x12340000` |
| `--p-unknown-bits` | Number of missing low factor bits | `--p-unknown-bits 16` |
| `--d-known-bits` | Number of known low d bits in partial-key mode | `--d-known-bits 20` |
| `--dp` | Leaked `d mod (p-1)` | `--dp 53 --attack dp_leak` |
| `--dq` | Leaked `d mod (q-1)` | `--dq 49 --attack dp_leak` |
| `--partial` | Interpret partial private-key material | `--key partial.pem --partial --attack partial_d` |
| `--sendtofdb` | Submit recovered factors externally | `--publickey key.pub --private --sendtofdb` |
| `--tests` | Tool's attack self-test mode, distinct from pytest | `--tests --attack fermat` |
| `--cleanup` | Request cleanup of `.pub` inputs after operation | `--publickey 'disposable/*.pub' --attack fermat --cleanup` |

Use `--cleanup` only on disposable copies. This reference does not run it against your challenge files. Passing a password as a CLI argument may expose it in process listings and shell history; the example is a throwaway CTF value.

### Which named attack should I select?

| Attack selector | Suitable clue / required data |
|---|---|
| `fermat` | Close p and q |
| `wiener` | Very small d |
| `boneh_durfee` | Small d beyond simple continued fractions |
| `cube_root` | Small e=3 message / root case |
| `common_factors` | Several moduli with shared primes |
| `hastads` | Same message, several moduli, matching ciphertexts |
| `common_modulus_related_message` | Same n, same message, different exponents |
| `franklin_reiter` | Two affine-related messages plus a,b |
| `stereotyped_message` | Known prefix/suffix, short unknown part |
| `short_pad` | Two encodings with short random-pad difference |
| `partial_p` | Aligned high bits of a factor and unknown-bit count |
| `partial_d`, `lattice`, `partial_q` | Supported partial key material; inspect exact adapter |
| `dp_leak` | Full leaked dp or dq |
| `small_crt_exp` | Small CRT private exponent |
| `pollard_p_1` | Smooth p−1 |
| `pollard_rho`, `brent`, `smallq` | Small factor / bounded general factoring |
| `ecm`, `ecm2` | Factor small enough for ECM backend |
| `factordb` | Previously factored modulus; network lookup |
| `roca` | Positive ROCA fingerprint and feasible parameters |
| `smallfraction` | p/q near a small rational |
| `siqs`, `qs`, `quadratic_sieve` | Small enough general composite; backend requirements vary |
| `all` | Broad queue; slower and may invoke network/external backends |

Other dynamically discovered modules cover specialized prime forms and experimental algorithms. Run `--help` for the exact names in your checkout and read `src/RsaCtfTool/attacks/{single_key,multi_keys}/NAME.py` before selecting an unfamiliar one. Selecting a module only invokes its implementation; it does not make a missing prerequisite true.

### Troubleshooting RsaCtfTool

| Symptom | What to check next |
|---|---|
| Unrecognized `--uncipher` | Use this version's `--decrypt`; compare `--help` |
| No `RsaCtfTool.py` | Use installed console command or `python -m RsaCtfTool` |
| Sage/backend not found | Verify executable PATH and interpreter environment |
| Attack “failed” instantly | Required leak flags, ciphertext count, imports or binaries |
| Broadcast gives no root | Ordered pairing, identical encoded message, GCDs and total modulus bound |
| Franklin–Reiter no result | Verify implementation relation `m2=a*m1+b` and input order |
| Coppersmith no result | Check units, aligned prefix, polynomial degree and realistic bound |
| GCD/inverse errors | May reveal shared factors; compute GCD before discarding |
| Private key recovered, no flag | Decode correct ciphertext and padding; plaintext may be another key |
| `--output` no longer parses as PEM | File may have appended multiple keys or mixed outputs |
| Long run without a result | Select attacks by evidence; set budgets and inspect logs |

## 5. Practice path and verification checklist

Work through the examples in this order: known factors → shared factors → Fermat → low roots → broadcast → common modulus → Wiener → Sage polynomials → related messages → Coppersmith → oracles. For each one, deliberately break one prerequisite and observe the failure. This builds recognition faster than running all attacks against every challenge.

```bash
python3 scripts/rsa_attacks.py --demo
sage -python scripts/sage_examples.py
sage -python scripts/make_rsa_lab.py
```

For a final answer in a CTF, check the actual challenge relation and encoding, re-encrypt recovered RSA candidates, confirm factors multiply back, and preserve enough bytes to distinguish a padded block from a short integer. For oracle scripts, save the query count and exact predicate. For brute force, record the searched range so “no match” has a precise meaning.

### Source and version notes

- RsaCtfTool: local `main.py`, `lib/utils.py`, `lib/algos.py`, attack adapters and `pyproject.toml` at commit `e1d8644e80aa48d08aa8e06d24c37cf81f3fb437`; [upstream repository](https://github.com/RsaCtfTool/RsaCtfTool).
- SageMath: local runtime **10.7**, with syntax and API references in the [official documentation](https://doc.sagemath.org/html/en/index.html). Online documentation may describe a newer release.
- [RSA attack survey](https://crypto.stanford.edu/~dabo/pubs/papers/RSA-survey.pdf), [Boneh–Durfee](https://crypto.stanford.edu/~dabo/pubs/abstracts/lowRSAexp.html), [Bleichenbacher](https://www.iacr.org/cryptodb/data/paper.php?pubkey=1037), and [Manger](https://www.iacr.org/archive/crypto2001/21390229.pdf) provide the original research context.
- [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) specifies RSA encodings; [Sage small_roots](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_modn_dense_ntl.html) documents the modular root interface.
- [jvdsn/crypto-attacks](https://github.com/jvdsn/crypto-attacks) is an implementation reference already present in this workspace. Local files may contain challenge-specific modifications; inspect before importing.

The bundled Python helpers and Sage toy demos are executable. Commands involving placeholder challenge files, partial keys or network oracles are integration templates; adapt their input and query handling to the challenge.
