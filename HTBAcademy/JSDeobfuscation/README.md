# Javascript Deobfuscation

1. [Obfuscation](#obfuscation)
1. [Deobfuscation](#deobfuscation)

## Obfuscation

* We can view the source code of a webpage using Developer Tools (Ctrl+U to view page source); JS can be written internally between ```<script>``` tags, or into separate '.js' file & referenced in HTML code.

* Obfuscation - technique used to make script more difficult to be read; usually done by obfuscation tools.

* Code minification - having entire code in a single line, saved with extension ```.min.js```; we can use tools like [javascript-minifier](https://javascript-minifier.com/) for this.

* For obfuscation, we can use tools such as [BeautifyTools](http://beautifytools.com/javascript-obfuscator.php) - this uses packing techniques, which usually convert all characters of code into a list/dictionary, and then refer to them using a function to rebuild original code.

* [obfuscator.io](https://obfuscator.io/) is another tool in which we can modify obfuscation settings such as encoding and rotation so that we don't get any remnants of the original code; other tools include [JSF](https://jsfuck.com/), [jjencode](https://utf-8.jp/public/jjencode.html) and [aaencode](https://utf-8.jp/public/aaencode.html).

## Deobfuscation

* To beautify minified JS code, we can use tools like ```Browser Dev Tools```, [Prettier](https://prettier.io/playground/) and [Beautifier](https://beautifier.io/).

* To deobfuscate packed code, we can use tools like [UnPacker](https://matthewfl.com/unPacker.html).

* Encoding & decoding is another common method used as part of obfuscation/deobfuscation:

  * base64 - ```echo <string> | base64``` to encode and ```echo <string> | base64 -d``` to decode
  
  * hex - ```echo <string> | xxd -p``` and ```echo <string> | xxd -p -r``` for hex encoding & decoding

  * rot13 (caesar) - use online tools like [CyberChef](https://gchq.github.io/CyberChef/)
