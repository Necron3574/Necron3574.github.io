---
layout: page
title: BCA-CTF 2022
description: Writeups for my solves in BCACTF 2022
---

I participated in this CTF with my team [Cryptonite](https://cryptonite.team/). It was a fun competition with easy to medium ranged challenges with a few hard ones. I usually major in Crypto but I tried my hand in all categories in this CTF. We ranked 48th at the end of the event.

# Writeups

## Crypto

### New Keyboard

> I bought a new keyboard, but it looks like it's typing gibberish!

- We are given a file with some gibberish text in it.
- On a few quick google searches and using the hints, I realised that the layout of the keyboard isnt qwerty, its [dvorak](https://en.wikipedia.org/wiki/Dvorak_keyboard_layout).
- Thus, using a Dvorak to qwerty converter [tool](https://awsm-tools.com/text/keyboard-layout) we get the flag.

### Hidden Frequencies
> I downloaded one of my friend's files and he got really defensive... it looks like gibberish but I think there might be more to it.

- This was another trivial challenge.
- We just have to calculate the frequencies of every character and convert the frequencies into their ascii equivalent to get the flag

### Really Secure Algorithm
> As BCA students, we are always pushing the limits of existing technologies! Today, I had a breakthrough and created a Really Secure Algorithm. Can you see if it's secure or not?

- This is again a generic rsa challenge where the primes are given. Since the primes are already given, solving it is trivial.  

```python
from Crypto.Util.number import *
c = ...
p = ...
q = ...
e = 65537
phi = (p-1)*(q-1)
d = inverse(e,phi)
print(pow(c,d,p*q))
```

- However, the plaintext was not bytes and was put in decimal encoded form so we had to deal with that.

### Chessy
> I've been learning a bit of chess recently. However, I can't seem to understand whatever this is. Can you help me? [File](https://objects.bcactf.com/bcactf/chessy/FEN.txt)

- This was an interesting challenge. We were given a file with a bunch of FEN texts.  
- FEN is a notation in chess which is used to describe a position on the board at any given point.  
- However, it was hinted that the challenge has nothing to do with chess. Thus, digging a little deeper into how FEN works, it notes down the name of the piece on every square on every row of the board. Since each row has 8 squares, I realised that the author tried to encode bytes using FEN.  
- Thus, if a square is empty, we take that byte as a `0` byte and if it has a piece, we assume its a `1`. Using this convention, after we decode all the bytes, and convert them to ascii we get our flag.  

```python

data = """2qp2kN/1qbpR1PN/1Bq2KQ1/1knR1r2/1Nq3Rb/1bn4n/1qr3nR/1BR3P1
1QP1PkR1/1PR2k1P/1KQk2NK/2rN1B1K/1KK4q/1nnr4/1R1PqRBQ/1qN1KBp1
1kB1Br1P/1bQ1p1Pk/1NB3Np/2rP2RQ/1bQ1Q3/1qK3PB/1r1Nbpkq/2RB1NkR
1np1B1b1/1QR4B/2Rk2q1/2pqq2p/1Q1pkbQK/2rn2rR/1KNk1p2/2bn1K2
1QpNrR1Q/1QB1K2n/1QNb1k1Q/2QKR2R/1np1PQ1b/1bP1br2/2rP2n1/2qR2pk
"""

flag = ""
for line in data.splitlines():
    flag_part = ""
    for byte in line.split("/"):
        bin_representation = ""
        for char in byte:
            if char in "12345678":
                bin_representation += int(char)*"0"
            else:
                bin_representation += "1"
        flag_part += chr(int(bin_representation,2))
    flag += flag_part[::-1]
print(flag)
```
### Funky Factors

> Okay. Turns out the last algorithm wasn't secure after all... I think it was because I gave you too much information! Can you see if its really unbreakable this time?

- Another typical RSA challenge with small factor. Putting the modulus in factordb spits the factors and then we can just decrypt like the previous challenge.


### Salty

> I found the flag factory!!! They keep their flags locked up. But I have insider info that they only use 4 digit alphanumeric passwords in lowercase. Can you get a flag?  

- This was a fun challenge. We are given a website where we need to login as admin. The website however has a log of all the salts used for every created user's password and its corresponding hash.  
- Looking at the hash, I could tell that it was an Md5 hash, but I needed to confirm it. Thus I made a random account with the password as `pass`.
- On creating this account, the log was updated with my new accounts hash and its salt which was `KCl-3e9d2`. I computed the Md5-hash of `passKCl-3e9d2` locally to see if it matches with the website's log and it did.
- So now we know its Md5 and that the password is lowercase alphanumeric 4 characters. We also know that the salt used was `NaCl-5ec99`. Thus, we can write a simple bruteforce script to solve the challenge and get the password.

```python
import hashlib
import string
import itertools

target_password_hash = "15c6e6a88cb9c73e4e82dc4f645bec65"
salt = b"NaCl-5ec99"

domain = string.ascii_lowercase + string.digits
for x in itertools.product(list(domain),repeat=4):
    password = "".join(i for i in x)
    hash = hashlib.md5(password.encode() + salt).hexdigest()
    if hash == target_password_hash:
        print(password)
        break
```

### A Fine Line

> I'm carefully drawing a fine line on this piece of paper, letting each portion guide the next... (Digits and letters are 0-9 and 10-35 in their usual orders, and the underscore is 36. {} are not encoded but should be added in afterwards. All letters are lowercase.)[File](https://objects.bcactf.com/bcactf/a-fine-line/chall.txt)

- This challenge was pretty straightforward too. It uses the affine cipher (as hinted in the title). The tricky part to it is, every pair of 2 characters act as a key to the next two characters.  
- Since it uses the above format to encrypt, we know that the first 2 charcters will be `bc` and wont be encrypted.
- Affine Cipher follows `y = (a*x + b) mod m` where y is the ciphertext and x is the plaintext. Since we know the domain of all characters used, we can say m = 36. And since the first 2 characters are `b` and `c`,  we can assume `a` = `ord('b')` and b = `ord('c')`.
- Once we get these , we can continually decrypt pairs of ciphertext to get every pair of plaintext by using the affine decryption method ` x = ( (y-c) * a_inv) mod m`.

```python
from Crypto.Util.number import *
plaintext = "bc"
ciphertext = "bx6ez_unufi3bm0r0xeb"
mapping = list("0123456789abcdefghijklmnopqrstuvwxyz_")
# affine cipher is (ax+b)modm = c
m = len(mapping)
for i in range(0,len(ciphertext),2):
    ciphertexts = (ciphertext[i],ciphertext[i+1])
    a = mapping.index(plaintext[-2])
    b = mapping.index(plaintext[-1])
    for c in ciphertexts:
        p = ((mapping.index(c)-b)%m*inverse(a,m))%m
        plaintext+= mapping[p]
print(plaintext)
```  

## Forensics

### Broken Image

> My friend said that he made a really cool drawing in MS Paint but I can't open it! Maybe my computer is broken? Or the image? I really don't know. Could you try opening it for me and telling me what it is?[File](https://objects.bcactf.com/bcactf/broken-image/chall.svg)

- This is a simple challenge, the file was not an svg it was a png so changing extension gives flag.

### My New Friend

> This is my new pen pal! He sent me this handsome picture of himself. Unfortunately, I forgot his name. Can you help me figure it out? [File](https://objects.bcactf.com/bcactf/my-new-friend/zimage.png)

- Another simple challenge, the flag was embedded in the lsb.
- Thus, by uploading the image on a lsb decoder, we cn get the flag. I used [Aperisolve](https://aperisolve.fr/) for the same.

### SuperGlue

> I accidentally glued my images together. Please help! [File](https://objects.bcactf.com/bcactf/superglue/chall)

- In this challenge, we are given a file which doesn't open properly. On viewing it in HxD (Hex Editor), we can see that there are four files concatenated against each other.
- Thus, we can seperate the files by searching for their magic bytes. On doing so, we can extract a `jpeg`, a `png`, a `gif` and a `riff` file.
- On opening all these files we get parts of the files.

### Gerbert's Secret

> This is my best friend Gerbert. He insists that he's a human like me, but I think he's hiding something. Anyways, he sent me this picture of himself. Can you help me find his secret?[File](https://objects.bcactf.com/bcactf/gerberts-secret/zgerberts.png)

- Weirdly, this challenge too had the flag in the RGB's lsb.
- Running an LSB Extracter will give you the flag.

### .bcapng

> BCACTF's latest creation: an image file format! It can represent black and white pixels, and isn't too efficient. The problem is, someone sent me a .bcapng file and I lost the program to view it. Could you tell me what it is? [File](https://objects.bcactf.com/bcactf/bcapng/chall.bcapng)

- In, this challenge we were given a file which has a series of `1` and `0` bits. We are also told in the chall description that these represent black and white pixels. Thus, our job was to use these given pixels to build an image.

- On opening the given file with HxD, we get a series of pixel bits. However, these bits are prepended by a 65_79. So I assumed that this was the resolution of the image.

- Thus, I used python's `pillow` library to map the pixel bits and generate a black and white image which had the flag. (I later changed the dimensions to 100x100 from 65x79 because I was missing out on some part of the flag).

```python
from PIL import Image
pixels = ...
def newImg():
    img = Image.new('1', (100, 100))
    for i in range(100):
        for j in range(100):
            try:
                img.putpixel((i,j),int(pixels[i*65+j]))
            except:
                pass
    return img
wallpaper = newImg()
wallpaper.show()
```

- This gives you the mirror image of the flag. Thus, I just used an oldschool hand mirror to get me the flag.

## Reversing

### Password Manager

> I forgot my password to the password checker which is stored in the password checker which I forgot the password to! Here's my password checker, can you help me remember the password? [File](https://objects.bcactf.com/bcactf/password-manager/PwdManager.py)

- We are given a dictionary using which, characters in a flag are substituted to random numbers.
- Thus, we can inverse the dictionary and substitute them back to get the flag.

```python
HASHEDPWD = '111210122915474114123027144625104141324527134638392719373948'
inv_map = {v: k for k, v in key.items()}
flag = ""
for i in range(0,len(HASHEDPWD),2):
    flag += inv_map[int(HASHEDPWD[i:i+2])]
print(flag)
```

### Ghost Game

> I love gaming in history class! This game is difficult to win though... I heard winning 10 times in a row leads to something good! [File](https://objects.bcactf.com/bcactf/ghost-game/GhostGame.py)

- In the source of this challenge, we can see that the we have the seed value used in the random function.
- As we know, python's random function is pseudorandom and deterministic and knowing the seed value used, enables us to generate the same randomness multiple times. Thus, using the same seed we can generate the same `randint(-1000,1000)%10` values to get the right doors.

```python
import random
random.seed(123049)
for _ in range(10):
    print(random.randint(-1000,1000)%10)
```

- Using these values, we can manually choose the doors and get the flag.

## Binary Exploitation

### Intro to Pwn

> So... you want to learn how to pwn?

- This was a simple unchecked signed integer bug.
- We needed 100 coins to buy flag but we had only 10. Alternatively we could buy something else worth 1 point. Thus we just buy `-1000` of that something else so that our balance increases and we can buy the flag.

### BOF Shop

> Welcome to the BOF Shop! Now you have the chance to buy your own flag! All you need to do is get a few coins first. Good luck.

##### Source

```C
#include <stdio.h>
#include <stdlib.h>

#define FLAG_BUFFER 100
int main() {
    char flag[FLAG_BUFFER];
    FILE *fp = NULL;
    char name[16];
    int balance = 0;

    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);

    puts("Hello there, welcome to the BOF Shop!");
    puts("What's your name?");
    printf("> ");
    gets(name);

    printf("Your balance: %d coins\n\n", balance);

    if (balance != 100) {
        puts("Sorry, but you need exactly 100 coins to purchase the flag.\nGoodbye.");
        exit(1);
    }

    fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        puts("Please add flag.txt to the present working directory to test this file.\n");
        puts("If you see this on the remote server, please contact admin.");
        exit(1);
    }

    fgets(flag, FLAG_BUFFER, fp);
    puts("Wow. Here, take the flag in exchange for your 100 coins.");
    puts(flag);
}
```

- In this challenge, we are given a C program that has a buffer overflow vulnerability on input.
- This program gives 100 bytes of space to char array `FLAG_BUFFER` and 16 bytes of space to a char array `name`. Our task is to modify the balance variable which is an integer. Thus, since we need to modify `balance`, we will have to overflow the space occupied on the stack by both `FLAG_BUFFER` and `name`.
- Thus, we can send a payload of length `116` in name and then the 117th byte will overwrite the balance variable.
- Since we want `balance == 100`, our `117th byte = 100 = "@"`.
- Therefore the payload is `"A" * 116 + '@'`
- Sending this payload overflows the buffer, overwrites balance and gives us the flag.


## Web Exploitation

### Real Deal HTML

> I have just made the most ultimate html site. This site, this html. This is the real deal

- Flag in source.

### Jason's Web Tarrot

> I just found this amazing tarot card website! Legend has it that if you can subscribe to Jason's tarot service, he'll give you a free flag! Sadly, he closed down the subscription section of the site. Can you get me my flag?

- In this challenge, the website assigns a jwt as a cookie and will only display the flag if the `issubscriber` parameter of the jwt is true.
- Solving this challenge is quie easy. The jwt in the backend did not disallow the `None` type in the algorithm. Thus, we can just change the `alg` header to `"None"` and then we can pass in any data without having to worry about its signature.
- Thus, we pass `"alg" : "None" and "issubscriber":true` and we get the flag/

## Miscellaneous

### Sequences

> I began storing my password with a super secure sequence, but I had to go make toast. Can you please retrieve my password? [File] (https://objects.bcactf.com/bcactf/Sequences/sequence.py)

- This challenge gives us a python function where we need to generate a famous sequence to get the flag.
- It additionally gives the first few values of the sequence. On googling the first few values`[0,1,3,6,2]`, we realise that it is the `[Recaman's Sequence](https://en.wikipedia.org/wiki/Recam%C3%A1n%27s_sequence)`.
- Thus, after writing a function to generate the Recaman's sequence, we get our flag.

```python
def gensequence():
    for i in range(5,10005):
        if (sequence[i-1]-i) > 0 and (sequence[i-1]-i) not in sequence:
            sequence.append(sequence[i-1]-i)
        else:
            sequence.append(sequence[i-1]+i)
```
