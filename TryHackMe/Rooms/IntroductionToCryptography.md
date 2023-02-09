# Introduction To Cryptography - Medium

1. [Introduction](#introduction)
2. [Symmetric Encryption](#symmetric-encryption)
3. [Asymmetric Encryption](#asymmetric-encryption)
4. [Diffie-Hellman Key Exchange](#diffie-hellman-key-exchange)
5. [Hashing](#hashing)
6. [PKI and SSL/TLS](#pki-and-ssltls)
7. [Authenticating with Passwords](#authenticating-with-passwords)

## Introduction

```markdown
1. You have received the following encrypted message:

“Xjnvw lc sluxjmw jsqm wjpmcqbg jg wqcxqmnvw; xjzjmmjd lc wjpm sluxjmw jsqm bqccqm zqy.” Zlwvzjxj Zpcvcol

You can guess that it is a quote. Who said it? - Miyamoto Musashi
```

## Symmetric Encryption

```markdown
1. Decrypt the file quote01 encrypted (using AES256) with the key s!kR3T55 using gpg. What is the third word in the file?

2. Decrypt the file quote02 encrypted (using AES256-CBC) with the key s!kR3T55 using openssl. What is the third word in the file?

3. Decrypt the file quote03 encrypted (using CAMELLIA256) with the key s!kR3T55 using gpg. What is the third word in the file?
```

## Asymmetric Encryption

```markdown
1. What is the first word of the original plaintext?

2. What is the last byte of p?

3. What is the last byte of q?
```

## Diffie-Hellman Key Exchange

```markdown
1. A set of Diffie-Hellman parameters can be found in the file dhparam.pem. What is the size of the prime number in bits?

2. What is the prime number’s last byte?
```

## Hashing

```markdown
1. What is the SHA256 checksum of the file order.json?

2. Open the file order.json and change the amount from 1000 to 9000. What is the new SHA256 checksum?

3. Using SHA256 and the key 3RfDFz82, what is the HMAC of order.txt?
```

## PKI and SSL/TLS

```markdown
1. What is the size of the public key in bits?

2. Till which year is this certificate valid?
```

## Authenticating with Passwords

```markdown
1. You were auditing a system when you discovered that the MD5 hash of the admin password is 3fc0a7acf087f549ac2b266baf94b8b1. What is the original password?
```
