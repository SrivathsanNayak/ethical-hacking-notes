# Emdee five for life - Easy

* In this challenge, we are given an IP:port address, which we can interact with in our browser.

* The webpage contains an input box, and we are given a string; our objective is to calculate MD5 hash of the string and submit it into the input.

* The challenge is that no matter how fast we hash the string and submit it, we will always get the message "Too slow!".

* In order to submit the response instantly, we would have to automate it.

* Initial step would be to check the source code:

```html
<html>
<head>
<title>emdee five for life</title>
</head>
<body style="background-color:powderblue;">
<h1 align='center'>MD5 encrypt this string</h1><h3 align='center'>ptiC41zOa0qhQMnoEg8q</h3><center><form action="" method="post">
<input type="text" name="hash" placeholder="MD5" align='center'></input>
</br>
<input type="submit" value="Submit"></input>
</form></center>
</body>
</html>
```

* We can automate this challenge using Python:

```python
#!/usr/bin/python

import requests
import re
from bs4 import BeautifulSoup
import hashlib

addr = 'http://167.99.202.139:32379'

sesh = requests.session()
#to use cookie in POST request

resp = sesh.get(addr)

soup = BeautifulSoup(resp.content, "lxml")
#to extract string from HTML
s = soup.h3.string

md5hash = hashlib.md5(s.encode()).hexdigest()
myobj = {'hash': md5hash}
#for input field to be submitted

print(sesh.post(addr, data = myobj).text)
```

```shell
python emdeefive.py
#gives response source code
#contains flag HTB{N1c3_ScrIpt1nG_B0i!}
```
