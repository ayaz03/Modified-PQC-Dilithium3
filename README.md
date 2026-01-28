# CRYSTALS-Dilithium3 Python Implementation
[!CAUTION]
This repository is intended strictly for research and educational purposes.

# Overview

This repository contains a modified Python implementation of CRYSTALS-Dilithium3, derived from the original dilithium-py project.
The modifications focus exclusively on Dilithium3, with changes applied to the key generation, signing, and signature verification logic.
All other variants (Dilithium2, Dilithium5 etc.) have been removed to keep the codebase minimal and suitable for experimentation and performance analysis.
This workflow demonstrates the core cryptographic operations used throughout the modified codebase.

# Purpose of Modifications.

The modifications in this repository are intended to support:
Performance evaluation of Dilithium3 signing and verification
Controlled experimentation with transaction and block-size models
Academic analysis in post-quantum blockchain and authentication systems
The implementation prioritizes clarity and experimentation, not production security.

# Original Source and Credits

This project is derived from the original open-source implementation:
Project: dilithium-py
Author: Giacomo Pope
Original Repository:
https://github.com/GiacomoPope/dilithium-py 

All credit for the original implementation belongs to the original author.
This repository introduces research-focused modifications limited to Dilithium3.

# License

This project is released under the MIT License, consistent with the original repository.


# Installation

This package is available as `dilithium-py` on
[PyPI](https://pypi.org/project/dilithium-py/):

```
pip install dilithium-py
```
### Dependencies

Originally, as with `kyber-py`, this project was planned to have zero
dependencies, however like `kyber-py`, to pass the KATs, we need  a 
deterministic CSRNG. The reference implementation uses
AES256 CTR DRBG. The project implemented this in [`ase256_ctr_drbg.py`](src/dilithium_py/drbg/ase256_ctr_drbg.py). 
However, this project has not implemented AES itself, instead it imports this from `pycryptodome`.

To install dependencies, run `pip install -r requirements.txt`.

If you're happy to use system randomness (`os.urandom`) then you don't need
this dependency.

# Core Parameters (Excerpt)
The following parameters are used to model transaction size, block constraints, and signing payloads for evaluation purposes:

# ----------------------- Parameters and Performance Evaluation -----------------------

BLOCK_SIZE_BYTES = 1000000       # 1 MB block cap
S_BASE_BYTES     = 186             # Non-crypto per-tx bytes (from 4k baseline)
SIG_BYTES        = 2973            # Dilithium signature bytes
ADDR_BYTES       = 32              # 32-byte key-hash (address), NOT full PK
FULL_PK_BYTES    = 1952            # Only used if USE_FULL_PK=True
USE_FULL_PK      = False           # False => 32-byte address model
FORCE_TX_COUNT: Optional[int] = 320  # Fix block to N tx, None = auto-pack

MSG_BYTES = 64   # payload length used in signing



![Performance comparison of Dilithium3 and modified implementation](https://github.com/ayaz03/Modified-PQC-Dilithium3/raw/main/Performance-Comparison.png)

**Figure:** Performance comparison of the Dilithium3 signature scheme and the proposed modified implementation. Subfigure (a) shows results using the modified parameter set, while subfigure (b) presents the original Dilithium3 parameters. The comparison demonstrates improved block utilization and better signing and verification efficiency for the proposed scheme.

These parameters are not part of the Dilithium specification, but are used to evaluate signing and verification costs in a block-style setting.
# ----------------------------------------------------------


# Dilithium3: Key Generation, Signing, and Verification

Below is a minimal illustrative example showing how the modified Dilithium3 implementation is used.
This snippet is included for introduction and clarity only.

from dilithium_py.dilithium import Dilithium3
import os, time

# Key generation
pk, sk = Dilithium3.keygen()

# Message to be signed
msg = os.urandom(MSG_BYTES)

# Signing
t0 = time.perf_counter()
sig = Dilithium3.sign(sk, msg)
t1 = time.perf_counter()

# Verification
valid = Dilithium3.verify(pk, msg, sig)
t2 = time.perf_counter()
assert valid, "Signature verification failed"
sign_time = t1 - t0
verify_time = t2 - t1

# ----------------------------------------------------------

### Polynomials

The file [`polynomials.py`](src/dilithium_py/polynomials/polynomials_generic.py) contains the classes 
`PolynomialRing` and 
`Polynomial`. This implements the univariate polynomial ring

$$
R_q = \mathbb{F}_q[X] /(X^n + 1) 
$$

The implementation is inspired by `SageMath` and you can create the
ring $R_{11} = \mathbb{F}_{11}[X] /(X^8 + 1)$ in the following way:

#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> x = R.gen()
>>> f = 3*x**3 + 4*x**7
>>> g = R.random_element(); g
5 + x^2 + 5*x^3 + 4*x^4 + x^5 + 3*x^6 + 8*x^7
>>> f*g
8 + 9*x + 10*x^3 + 7*x^4 + 2*x^5 + 5*x^6 + 10*x^7
>>> f + f
6*x^3 + 8*x^7
>>> g - g
0
```

### Modules

The file [`modules.py`](src/dilithium_py/modules/modules_generic.py) contains the classes `Module` and `Matrix`.
A module is a generalisation of a vector space, where the field
of scalars is replaced with a ring. In the case of Dilithium, we 
need the module with the ring $R_q$ as described above. 

`Matrix` allows elements of the module to be of size $m \times n$
For Dilithium, we need vectors of length $k$ and $l$ and a matrix
of size $l \times k$. 

As an example of the operations we can perform with out `Module`
lets revisit the ring from the previous example:

#### Example

```python
>>> R = PolynomialRing(11, 8)
>>> x = R.gen()
>>>
>>> M = Module(R)
>>> # We create a matrix by feeding the coefficients to M
>>> A = M([[x + 3*x**2, 4 + 3*x**7], [3*x**3 + 9*x**7, x**4]])
>>> A
[    x + 3*x^2, 4 + 3*x^7]
[3*x^3 + 9*x^7,       x^4]
>>> # We can add and subtract matricies of the same size
>>> A + A
[  2*x + 6*x^2, 8 + 6*x^7]
[6*x^3 + 7*x^7,     2*x^4]
>>> A - A
[0, 0]
[0, 0]
>>> # A vector can be constructed by a list of coefficents
>>> v = M([3*x**5, x])
>>> v
[3*x^5, x]
>>> # We can compute the transpose
>>> v.transpose()
[3*x^5]
[    x]
>>> v + v
[6*x^5, 2*x]
>>> # We can also compute the transpose in place
>>> v.transpose_self()
[3*x^5]
[    x]
>>> v + v
[6*x^5]
[  2*x]
>>> # Matrix multiplication follows python standards and is denoted by @
>>> A @ v
[8 + 4*x + 3*x^6 + 9*x^7]
[        2 + 6*x^4 + x^5]
```

### Number Theoretic Transform

We can transform polynomials to NTT form and from NTT form
with `poly.to_ntt()` and `poly.from_ntt()`.

When we perform operations between polynomials, `(+, -, *)`
either both or neither must be in NTT form.

```py
>>> f = R.random_element()
>>> f == f.to_ntt().from_ntt()
True
>>> g = R.random_element()
>>> h = f*g
>>> h == (f.to_ntt() * g.to_ntt()).from_ntt()
True
```
