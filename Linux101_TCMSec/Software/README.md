# Installing Software

* Debian-based systems:

  * ```apt update``` - update info

  * ```apt list --upgradable``` - check if installed apps can be upgraded

  * ```apt upgrade``` - upgrade existing packages

  * ```apt search pdftk``` - search for package

  * ```apt show pdftk``` - show info about package

  * ```apt install pdftk-java``` - install package

  * ```apt remove pdftk-java``` - uninstall package

  * ```apt purge pdftk-java``` - uninstall package and remove config files

  * ```apt autoremove``` - remove unrequired dependencies

* RedHat systems:

  * ```yum check-update``` - check for updates

  * ```yum update``` - check for updates and upgrade installed packages

  * ```yum search qpdf``` - search package

  * ```yum info qpdf``` - info on package

  * ```yum install qpdf``` - install package

  * ```yum remove qpdf``` - remove package

* Manually installing software:

  ```shell
  wget <link to archive>
  # download source code for app

  tar xfz code.tar.gz
  # extract from archive

  cd code

  # go through installation notes if any

  ./configure
  # creates a Makefile

  make
  # compile code

  sudo make install
  # install app
  ```
