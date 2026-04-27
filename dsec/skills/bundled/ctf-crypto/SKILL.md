# SKILL: CTF Cryptography

## Description
Crypto challenge patterns and attack methodologies.

## Trigger Phrases
crypto, rsa, aes, cipher, hash, decrypt, modular

## Methodology

### RSA Attacks
1. Small e with small message → cube root attack
2. Common modulus attack (same n, different e)
3. Wiener's attack (large e, small d)
4. Factorize n: factordb.com, yafu, msieve
5. Coppersmith short pad attack
6. Hastad broadcast attack (same m, multiple (n,e) pairs)

### AES / Block Cipher
1. ECB mode → detect patterns, block reordering
2. CBC bit-flipping → modify ciphertext to alter plaintext
3. Padding oracle → decrypt without key
4. Key reuse → XOR ciphertexts

### Classical Ciphers
1. Caesar/ROT13: `python3 -c "import codecs; print(codecs.decode(s, 'rot_13'))"`
2. Vigenère: Kasiski analysis, frequency analysis
3. Substitution: quipqiup.com

### Hash
1. Length extension attack (MD5, SHA1)
2. Hash collision (birthday attack)
3. Rainbow tables: crackstation.net
