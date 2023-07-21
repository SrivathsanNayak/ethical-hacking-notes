# iOS Dynamic Analysis

* For dynamic analysis, we can break SSL pinning if using ```Burp Suite``` or ```Proxyman``` does not work.

* We can attempt to use ```Objection``` to patch the ipa and disable SSL pinning - if this too does not work, we can use a jailbroken iOS device and use tools like ```SSL KillChain``` to break SSL pinning.

* ```Objection``` can be installed using ```pip3 install frida-tools``` and ```pip3 install objection```.

* ```objection patchipa``` can be used to patch the ipa; ```objection explore``` can be used to hook onto the app (once it is installed in phone).

* [Jailbreaking](https://checkra.in/) has to be used as a last resort, but it is vital for iOS pentesting.

* [SSL killswitch](https://github.com/nabla-c0d3/ssl-kill-switch2) tool can also be used to break SSL pinning, run on a jailbroken iOS device.
