# Gaining Foothold

* We can generate a wordlist of names by enumerating the given website - this can be used later during password spraying or brute-forcing.

* For creating possible usernames, we can use a tool like [NameMash](https://gist.github.com/superkojiman/11076951).

* Using ZAP or Burp Suite, we can then brute-force the Roundcube Webmail login page with the generated usernames and a list of common passwords - this gives us a set of valid creds.

* Once we have access to Roundcube Webmail, we can create a phishing campaign using [Out-Word.ps1](https://github.com/samratashok/nishang/blob/master/Client/Out-Word.ps1) tool, which allows us to inject our payload into a .doc file; we can do this phishing campaign using a .hta file as well.

* The injected payload should allow us to give a reverse shell when the victim opens the .doc file and enables the macro.
