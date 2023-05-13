# Users and Groups

* ```users```, ```who``` and ```w``` commands can be used to check the users logged into the system.

* ```/etc/passwd``` file contains user info like username and home directory location.

* ```/etc/shadow``` contains the username and hash.

* ```/etc/group``` contains info about groups.

* File and directory permissions can be viewed using ```ls -la```.

* Execute permission for a directory determines if the user can execute a command inside the directory.

* Modifying permissions and ownership:

  * ```chmod g-w hello.txt``` - removes group-write permission

  * ```chmod a=,u=r hello.txt``` - changes permission for all users to none, and adds read permission for user (file owner)

  * ```chmod 664 hello.txt``` - read-write permission for user & group, and only read permissions for everyone else

  * ```sudo chown mike hello.txt``` - change user ownership of file

  * ```sudo chgrp mike hello.txt``` - change group ownership of file

* ```sudo -u anotheruser cat restricted.txt``` allows us to read the file as another user.

* ```su newuser``` can be used to switch user.

* ```passwd``` can be used to change the user's password; ```sudo passwd newuser``` to change another user's password.
