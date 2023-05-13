# Filesystem

* ```man hier``` shows us a description of the Linux filesystem hierarchy.

* Despite multiple directories and mount points being used, they are all part of the same filesystem.

* The config for how the different drive partitions are mounted can be found in ```/etc/fstab```.

* ```mount``` can be used to mount partitions at different mount points on filesystem.

* ```df``` displays disk filesystem space usage of all mounted partitions, and ```du``` displays disk usage of files & directories on disk.

* Absolute paths always start from the root of the filesystem and ignore current working directory; relative paths are paths from current working directory.

* ```ls -l file.txt``` shows the last modification time of a file; to update the modification time, we can run ```touch file.txt``` - but this will create the file if it does not exist.

* For filename with spaces, we can either escape the space character like ```cat file\ name.txt```, or place the enter name in quotes like ```cat "file name.txt"```.

* Globbing examples:

  * ```ls file*.txt``` - matches text files starting with 'file'

  * ```ls file?.txt``` - matches text files starting with 'file' and having another character after that

  * ```ls **/*.txt``` - matches text files across directories

  * ```ls file[123].txt``` - matches text files starting with 'file' and having '1', '2', or '3' after that

  * ```ls file[a-zA-Z].txt``` - matches text files starting with 'file' and having any of the letters in the provided range after that

* ```ln``` can be used to create hard and soft links:

  * Hard link points to physical location of file on storage - ```ln hello.txt hello-hardlink.txt``` creates a hard link for 'hello.txt'.
  
  * Changes in original file will follow in hard link - original file can be deleted, but hard link still persists.

  * Soft (symbolic) link references file or directory on filesystem - ```ln -s hello.txt hello-softlink.txt``` creates a soft link.

  * If the resource is removed from filesystem, the soft link will not work.

* Compressing & archiving files:

  * ```zip tmp/backup.zip f1.txt f2.txt f3.txt``` - creates zip file

  * ```unzip -l tmp/backup.zip``` - lists contents of zip file

  * ```zip -r tmp/backup-dir.zip dir1 dir2``` - creates zip file of directory contents

  * ```tar cvf backup.tar file?.txt dir?``` - archives files and directories matching the format

  * ```tar tvf backup.tar``` - lists contents of archive

  * ```tar xvf backup.tar``` - extracts files from archive

  * ```gzip backup.tar``` - compresses archive

  * ```gunzip backup.tar.gz``` - decompresses archive

* Searching in filesystem:

  * ```find . -name 'file*.txt'``` - finds files with specific format in current & sub-directories

  * ```find . -iname 'file*.txt'``` - case-insensitive search

  * ```locate file.txt``` - searches from a database of file names from entire filesystem
