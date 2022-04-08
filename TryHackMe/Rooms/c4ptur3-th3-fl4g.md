# c4ptur3-th3-fl4g - Easy

* Translation & Shifting:

  * c4n y0u c4p7u23 7h3 f149? - can you capture the flag?

  * 01101100 01100101 01110100 01110011 00100000 01110100 01110010 01111001 00100000 01110011 01101111 01101101 01100101 00100000 01100010 01101001 01101110 01100001 01110010 01111001 00100000 01101111 01110101 01110100 00100001 - lets try some binary out!

  * MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM====== - base32 is super common in CTF's

  * RWFjaCBCYXNlNjQgZGlnaXQgcmVwcmVzZW50cyBleGFjdGx5IDYgYml0cyBvZiBkYXRhLg== - Each Base64 digit represents exactly 6 bits of data.

  * 68 65 78 61 64 65 63 69 6d 61 6c 20 6f 72 20 62 61 73 65 31 36 3f - hexadecimal or base16?

  * Ebgngr zr 13 cynprf! - Rotate me 13 places!

  * *@F DA:? >6 C:89E C@F?5 323J C:89E C@F?5 Wcf E:>6DX - You spin me right round baby right round (47 times)

  * \- . .-.. . -.-. --- -- -- ..- -. .. -.-. .- - .. --- -.

    . -. -.-. --- -.. .. -. --. - TELECOMMUNICATION  ENCODING

  * 85 110 112 97 99 107 32 116 104 105 115 32 66 67 68 - Unpack this BCD

  * LS0tLS0gLi0tLS0gLi0tLS0gLS0tLS0gLS0tLS0gLi0tLS0gLi0tLS0gLS0tLS0KL... (string too large to be shown here) - Let's make this a bit trickier...

  <details>
  <summary>Explanation</summary>
  This was first converted from base64, as it ended with an equal sign. This gives us a sequence of dashes, so we can translate it from Morse Code, giving us a sequence of 0s and 1s. Binary to text gives us a text sequence. It can be cracked using ROT47, giving us a sequence of decimal numbers, which can be translated from decimal, giving us the answer.
  </details>

<br>

* Spectrograms:

  * We have to get spectrogram of the audio file to uncover the message: ```sox secretaudio.wav -n spectrogram```

  * The generated spectrogram contains the answer.

<br>

* Steganography:

  * We have to use steganography to get the hidden message: ```steghide extract -sf stegosteg.jpg```

  * This gives us a text file, which contains the answer.

<br>

* Security through obscurity:

  * The downloaded .jpg file contains the two clues: ```strings meme.jpg```

  * This gives us all the readable text inside the image file, giving us the required answers.

* Reference: <https://infosecwriteups.com/beginners-ctf-guide-finding-hidden-data-in-images-e3be9e34ae0d>
