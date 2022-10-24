# Explosion - Very Easy

```shell
rustscan -a 10.129.1.13 --range 0-65535 --ulimit 5000 -- -sV

xfreerdp /u:Administrator /v:10.129.1.13 /port:3389
#login without password allowed for Administrator
```

```markdown
Open ports & services:

  * 135 - msrpc
  * 139 - ssn
  * 445 - microsoft-ds
  * 3389 - mst-wbt-server
  * 5985 - http
  * 47001 - http
  * 49664-49671 - msrpc

According to the given clues, as this is a room with account misconfigurations, we can try for logging in as Administrator into RPC using xfreerdp.

We can login without a password as given in the question - it works and we can get root flag from desktop
```

1. What does the 3-letter acronym RDP stand for? - Remote Desktop Protocol

2. What is a 3-letter acronym that refers to interaction with the host through a command-line interface? - CLI

3. What about graphical user interface interactions? - GUI

4. What is the name of an old remote access tool that came without encryption by default and listens on TCP port 23? - telnet

5. What is the name of the service running on port 3389 TCP? - ms-wbt-server

6. What is the switch used to specify the target host's IP address when using xfreerdp? - /v:

7. What username successfully returns a desktop projection to us with a blank password? - Administrator

8. Submit root flag - 951fa96d7830c451b536be5a6be008a0
