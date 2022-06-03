---
layout: page
title: dhke-adventure
description: Writeup for crypto challenge dhke-adventure in UIUCTF2021
---

# DHKE-Adventure
This was a writeup for the crypto challenge dhke_adventure in UIUCTF2021 which I won a prize for so I thought I'd put this up.
## Description
```
Za smoother warudo.
nc dhke-adventure.chal.uiuc.tf 1337
```
## Source
```python
from random import randint
from Crypto.Util.number import isPrime
from Crypto.Cipher import AES
from hashlib import sha256

print("I'm too lazy to find parameters for my DHKE, choose for me.")
print("Enter prime at least 1024 at most 2048 bits: ")
# get user's choice of p
p = input()
p = int(p)
# check prime valid
if p.bit_length() < 1024 or p.bit_length() > 2048 or not isPrime(p):
    exit("Invalid input.")
# prepare for key exchange
g = 2
a = randint(2,p-1)
b = randint(2,p-1)
# generate key
dio = pow(g,a,p)
jotaro = pow(g,b,p)
key = pow(dio,b,p)
key = sha256(str(key).encode()).digest()

with open('flag.txt', 'rb') as f:
    flag = f.read()

iv = b'uiuctf2021uiuctf'
cipher = AES.new(key, AES.MODE_CFB, iv)
ciphertext = cipher.encrypt(flag)

print("Dio sends: ", dio)
print("Jotaro sends: ", jotaro)
print("Ciphertext: ", ciphertext.hex())
```
## Solution
* So this is the second challenge based on the Diffie-Hellman key exchange (DHKE). In the previous challenge, the value of the prime was small which made it easy to recover the shared secret key.
* However, this challenge does not use small primes. Infact, in this challenge you are allowed to submit your own prime which will be used as `p` in the key exchange.
* Now since you are allowed to choose your own prime, why not choose something small like 2 since we already know that small primes are weak? That would work normally, but sadly the server asserts that the prime which you send must be greater than 1024 bits and lesser than 2048 bits.
* In addition to this it also adds a check to make sure that the prime you sent is actually a prime (as shown in snippet below).

  ```python
  if p.bit_length() < 1024 or p.bit_length() > 2048 or not isPrime(p):
    exit("Invalid input.")
  ```

* Thus we can now discard the ideas of inserting small primes and think of a smarter way to exploit this. For that, lets go back to what the security of the Diffie-Hellman key exchange actually relies on.
### Discrete Logarithm Problem
* The security of the Diffie-Hellman key exchange relies on the discrete logarithm problem. Normally if we used just integers to facilitate our DHKE, then a normal logarithm would suffice. However since we are performing our DHKE over a finite field, we need to use whats called a discrete logarithm. Mathematically this looks like:
```Field Prime = p
Generator = g
Alice secret key = a
Alice calculates her public key (A) as pow(g,a,p)
Now knowing A , g and p. To find 'a' we use what's known as a discrete logarithm.
a = A.discrete_log(g,p)
```
* Now, a discrete logarithm of something over a prime field of 1024 bits is very hard to calculate. The complexity of calculating the discrete log of this order is similar to factorizing the order of the field. So how do we solve the challenge?
### Pohlig Hellman Algorithm
* This is an algorithm which is used to compute discrete logs when the prime used has an order that is smooth.
* A smooth number is essentially a number which comprises of small prime factors.
* The order of a prime number p is `phi(p) = p-1`
* Thus if the prime satisfies this condition, then the algorithm can successfully find the discrete logarithm in polynomial time.
* So now we know our exploit. If we create a prime p such that p-1 is smooth, we can use the pohlig hellman algorithm to find the discrete log of `A,g` over `p` to recover `a`.
## Exploit
### Generating a suitable prime
* Now that we know our exploit, we just need to generate a prime of smooth order. We can do that in many ways. Below is the algorithm I used to generate the prime.
```python
primes = [2,3,5,7,11,13,19,23,29,31,37,41,47,53]
num = 1
while isPrime(num+1) != True or num.bit_length() < 1024:
    if num.bit_length() > 2048:
        num = 1
    num *= primes[random.randint(0,len(primes)-1)]
p = num + 1
```
* This algorithm just keeps multiplying random primes from a predefined list.
* Once the generated num exceeds 1024 bits, it checks if `num+1` is prime.
* If this condition passes, it breaks out of the loop and you get the value of p.
* If the prime exceeds 2048 bits, `num` is reset to 1 and the loop starts over.
### Computing the discrete log
* Now that we have the prime, we can get the corresponding public keys of Alice and Bob or in this case Dio and Jotaro (everyone loves a JoJo reference :P).
* Let A = public key of Alice (Dio) = `pow(g,a,p)`
* Let B = public key of Bob (Jotaro) = `pow(g,b,p)`
* We can take either A or B and use the pohlig hellman algorithm to find its discrete log with g over p to get a.
* We can use the sage module for this. (Sage has a discrete_log function that uses the Pohlig-Hellman algorithm by default).
```python
from sage.all import *
g = Mod(2,p) #since the value of the generator is 2 and the field prime is p
a = discrete_log(A,g)
```
* Now we have succesfully computed the discrete_log and recovered Alice's (Dio's) secret key `a`.
* Also note how I said, the complexity of calculating the discrete log problem is similar to that of factorizing problem.
* Well if you think about it, factorizing the order is pretty easy. Hence their complexities are comparable.
### Recovering the shared secret and getting the flag
* Now that we have `a` recovering the shared secret is trivial.
* The shared secret `s = pow(B,a,p)`. This works because
```
B = pow(g,b,p)
==> s = pow(B,a,p) = pow(pow(g,b,p),a,p) = pow(g,a*b,p)
```
* Once we have the shared secret, we can get the key and decrypt the flag by replicating the source.
* The ciphertext is encrypted with AES-CFB. The iv is given to you `b'uiuctf2021uiuctf'`.
* Hence with the key we calculated, we can decrypt the flag.
```python
secret = pow(B,a,n)
key = sha256(str(secret).encode()).digest()
iv = b'uiuctf2021uiuctf'
cipher = AES.new(key, AES.MODE_CFB, iv)
flag = cipher.decrypt(ct)
print(flag)
```
### Full exploit code
```python
from sage.all import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import sha256
from pwn import *
import random
primes = [2,3,5,7,11,13,19,23,29,31,37,41,47,53]
num = 1
while isPrime(num+1) != True or num.bit_length() < 1024:
    if num.bit_length() > 2048:
        num = 1
    num *= primes[random.randint(0,len(primes)-1)]
p = num + 1
r = remote("dhke-adventure.chal.uiuc.tf",1337)
print(r.recvline())
print(r.recvline())
r.sendline(str(n))
A = int(r.recvline().decode().strip("Dio sends:  ").strip())
B = int(r.recvline().decode().strip("Jotaro sends:  ").strip())
ct = bytes.fromhex(r.recvline().decode().strip("Ciphertext:  "))
# If you dont have sage setup for python, you can do this independently on sagecell and put the value back in the script manually.
g = sage.Mod(2,p)
a = sage.discrete_log(A,g)
sharedsecret = pow(B,a,n)
key = sha256(str(sharedsecret).encode()).digest()
iv = b'uiuctf2021uiuctf'
cipher = AES.new(key, AES.MODE_CFB, iv)
flag = cipher.decrypt(ct)
print(flag)
```
## Links for further information
1. https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm
2. https://en.wikipedia.org/wiki/Discrete_logarithm
3. https://www.comparitech.com/blog/information-security/Diffie-Hellman-key-exchange/
