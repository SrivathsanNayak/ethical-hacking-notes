# Introduction To Cryptography - Medium

1. [Introduction](#introduction)
2. [Symmetric Encryption](#symmetric-encryption)
3. [Asymmetric Encryption](#asymmetric-encryption)
4. [Diffie-Hellman Key Exchange](#diffie-hellman-key-exchange)
5. [Hashing](#hashing)
6. [PKI and SSL/TLS](#pki-and-ssltls)
7. [Authenticating with Passwords](#authenticating-with-passwords)

## Introduction

* Caesar cipher - substitution cipher which shifts the letters by a fixed number of places to the left/right; can use a key between 1 and 25.

* Transposition cipher - encrypts the message by changing order of the letters.

* We can use resources such as [quipquip](https://www.quipqiup.com/) to decrypt simple substitution ciphers.

```markdown
1. You have received the following encrypted message:

“Xjnvw lc sluxjmw jsqm wjpmcqbg jg wqcxqmnvw; xjzjmmjd lc wjpm sluxjmw jsqm bqccqm zqy.” Zlwvzjxj Zpcvcol

You can guess that it is a quote. Who said it? - Miyamoto Musashi
```

## Symmetric Encryption

* Terminology:

  * Cryptographic algorithm/cipher - defines encryption/decryption processes
  * Key - algorithm needs a key to convert plaintext into ciphertext and vice versa
  * Plaintext - original message to be encrypted
  * Ciphertext - message in encrypted form

* Symmetric encryption algorithm uses the same key for encryption/decryption.

* Block cipher encryption algorithm converts input plaintext into blocks, and encrypts each block.

* Stream cipher encryption algorithm encrypts the plaintext byte by byte.

* Programs used for symmetric encryption:

  * GNU Privacy Guard:

  ```shell
  gpg --version
  #check supported ciphers

  gpg --symmetric --cipher-algo CIPHERNAME message.txt
  #encrypt file in binary openPGP format
  #output saved as message.txt.gpg

  gpg --armor --symmetric --cipher-algo CIPHERNAME message.txt
  #encrypt file in ASCII armored output

  gpg --output original.txt --decrypt message.gpg
  #decrypt file
  ```

  * OpenSSL Project:

  ```shell
  openssl aes-256-cbc -e -in message.txt -out encrypted_message
  #encrypt file

  openssl aes-256-cbc -d -in encrypted_message -out original_message.txt
  #decrypt file

  openssl aes-256-cbc -pbkdf2 -iter 10000 -e -in message.txt -out encrypted_message
  #encrypt using PBKDF2 with 10000 iterations

  openssl aes-256-cbc -pbkdf2 -iter 10000 -d -in encrypted_message -out original_message.txt
  #decrypt in similar way
  ```

```markdown
1. Decrypt the file quote01 encrypted (using AES256) with the key s!kR3T55 using gpg. What is the third word in the file? - waste

2. Decrypt the file quote02 encrypted (using AES256-CBC) with the key s!kR3T55 using openssl. What is the third word in the file? - science

3. Decrypt the file quote03 encrypted (using CAMELLIA256) with the key s!kR3T55 using gpg. What is the third word in the file? - understand
```

## Asymmetric Encryption

* In asymmetric encryption algorithm, we would generate a key pair (public key and private key) - public key can be public, but private key should be saved securely.

* RSA:

```shell
openssl genrsa -out private-key.pem 2048
#generates RSA private key of size 2048 bits

openssl rsa -in private-key.pem -pubout -out public-key.pem
#generates public key

openssl rsa -in private-key.pem -text -noout
#shows RSA variables for p,q,N,e,d

#if we have recipient's public key, we can encrypt
openssl pkeyutl -encrypt -in plaintext.txt -out ciphertext -inkey public-key.pem -pubin

#recipient can decrypt it
openssl pkeyutl -decrypt -in ciphertext -inkey private-key.pem -out decrypted.txt
```

```markdown
1. What is the first word of the original plaintext? - Perception

2. What is the last byte of p? - e7

3. What is the last byte of q? - 27
```

## Diffie-Hellman Key Exchange

* Diffie-Hellman - asymmetric encryption algorithm; allows the exchange of a secret over a public channel.

```shell
openssl dhparam -out dhparams.pem 2048
#generate DH parameters

openssl dhparam -in dhparams.pem -text -noout
#view parameters
```

```markdown
1. A set of Diffie-Hellman parameters can be found in the file dhparam.pem. What is the size of the prime number in bits? - 4096

2. What is the prime number’s last byte? - 4f
```

## Hashing

* Cryptographic hash function - algorithm that takes data as input and returns a fixed size value (message digest or checksum) as output.

* Hashing is used in storing passwords and detecting modifications.

* HMAC (hash-based message authentication code) - message authentication code (MAC) that uses a cryptographic key and hash function.

* HMAC needs a secret key, inner pad and outer pad:

```shell
hmac256 s!Kr37 message.txt
#calculate HMAC using key

sha256hmac message.txt --key s!Kr37
#HMAC using sha256hmac with key, same output
```

```markdown
1. What is the SHA256 checksum of the file order.json? - 2c34b68669427d15f76a1c06ab941e3e6038dacdfb9209455c87519a3ef2c660

2. Open the file order.json and change the amount from 1000 to 9000. What is the new SHA256 checksum? - 11faeec5edc2a2bad82ab116bbe4df0f4bc6edd96adac7150bb4e6364a238466

3. Using SHA256 and the key 3RfDFz82, what is the HMAC of order.txt? - c7e4de386a09ef970300243a70a444ee2a4ca62413aeaeb7097d43d2c5fac89f
```

## PKI and SSL/TLS

* Key exchanges such as the Diffie-Hellman key exchange are not immune to MITM attacks.

* PKI (Public Key Infrastructure) is ensured in websites, where an encrypted connection is secured over HTTPS with a valid cert.

* For a certificate to get signed by a certificate authority, we need to:

  * Generate CSR (Certificate Signing Request) - create cert and send public key to be signed by a third party.
  
  * Send CSR to CA (Certificate Authority) - trusted CA signs the certificate.

```shell
openssl req -new -nodes -newkey rsa:4096 -keyout key.pem -out cert.csr
#generate cert signing request
#-nodes to save private key without passphrase

openssl req -x509 -newkey -nodes rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
#generate self-signed cert
#-x509 indicates self-signed instead of CSR

openssl x509 -in cert.pem -text
#view cert
```

* Once the client (browser) receives a signed cert it trusts, the SSL/TLS handshake takes place; purpose is to agree on ciphers and secret key.

```markdown
1. What is the size of the public key in bits? - 4096

2. Till which year is this certificate valid? - 2039
```

## Authenticating with Passwords

* Rainbow tables - contain lists of passwords along with their hash values.

* Salt - a random value that can be appended to passwords before hashing it.

* We can also store passwords by using key derivation functions such as PBKDF2 (Password-Based Key Derivation Function 2) to make it more secure.

```markdown
1. You were auditing a system when you discovered that the MD5 hash of the admin password is 3fc0a7acf087f549ac2b266baf94b8b1. What is the original password? - qwerty123
```
