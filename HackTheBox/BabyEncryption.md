# BabyEncryption - Very Easy

* given scenario - a confidential message file is found that needs to be decrypted

* extract the contents of the ZIP file using the password 'hackthebox'

* the ZIP file has a 'chall.py' script and the encrypted message 'msg.enc'

* checking the Python script:

    ```py
    import string
    from secret import MSG

    def encryption(msg):
        ct = []
        for char in msg:
            ct.append((123 * char + 18) % 256)
        return bytes(ct)

    ct = encryption(MSG)
    f = open('./msg.enc','w')
    f.write(ct.hex())
    f.close()
    ```

    * the script imports a variable 'MSG' from the file/module 'secret.py'

    * the encryption function iterates over each character of the 'MSG' variable and does the following maths on it - ```(123 * char + 18) % 256)```

    * the ```% 256``` operation is to keep the 'char' in the byte range of 0-255

    * the modulo operation makes sense only if the 'MSG' variable is in bytes; if it was in string type it would not work

    * the result is returned as a list of bytes, and written to the 'msg.enc' file, and converts the bytes into a hexadecimal string

* we can decrypt this in the same way to recover the original message

* decoding the original encryption function step-by-step (used ChatGPT for this to understand the logic):

    * ```ct = (123 * char + 18) % 256``` - subtract 18 from both sides

    * ```ct - 18 = (123 * char) % 256``` - now, we need to find its multiplicative modular inverse

    * the modulo inverse formula, as per this case, is ```123 * x = 1 (% 256)```, where x has to be in the range of 1 to 255 (256 minus 1)

    * using an online inverse modulo calculator, we find that x = 179, so that can be used as the modulo inverse

    * apply the modulo inverse - and multiply by 179 to keep the sides equated

    * ```((ct - 18) % 256) * 179 = char``` - this gives the decryption rule

* we can apply rest of the logic with the decryption rule in our script:

    ```py
    # read file contents
    with open('./msg.enc','r') as file:
        f = file.read()

    b = bytes.fromhex(f)
    # decode from hex to bytes

    pt = []
    for byte in b:
        p = (179 * (byte - 18)) % 256
        pt.append(p)

    # convert back to bytes and print
    print(bytes(pt))
    ```

* running the script gives us the flag
