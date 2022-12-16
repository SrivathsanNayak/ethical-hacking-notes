from pwn import *
import sys

if len(sys.argv) != 2:
    print("Invalid arguments!")
    print("Usage: {} <sha256sum>".format(sys.argv[0]))
    exit()

reqd_hash = sys.argv[1]
pass_file = "/usr/share/wordlists/rockyou.txt"
attempts = 0

with log.progress("Attempting to crack: {}!\n".format(reqd_hash)) as p:
    with open(pass_file, 'r', encoding='latin-1') as pass_list:
        for password in pass_list:
            password = password.strip("\n").encode('latin-1')
            #sha256sum for hash of file
            #sha256sumhex for hash of string
            pass_hash = sha256sumhex(password)
            p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), pass_hash))
            if pass_hash == reqd_hash:
                p.success("Password hash found after {} attempts! {} hashes to {}".format(attempts, password.decode('latin-1'), reqd_hash))
                exit()
            attempts += 1
        p.failure("Password hash not found!")
