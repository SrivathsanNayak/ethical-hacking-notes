# OWASP Juice Shop

1. [Installation](#installation)

## Installation

```shell
#install docker
sudo apt-get update && sudo apt-get install -y docker.io

#pull docker image
sudo docker pull bkimminich/juice-shop

#run docker image
sudo docker run --rm -p 3000:3000 bkimminich/juice-shop
#now we can access website on <http://127.0.0.1:3000>
```

* References (to be used throughout this section):

  * [Pwning OWASP Juice Shop](https://pwning.owasp-juice.shop/)
  * [OWASP Juice Shop GitHub Repo](https://github.com/juice-shop/juice-shop)

* While using Burp Suite for intercepting requests, we can add the target website to scope under the Target section, and enable 'show only in-scope items under 'Filter settings'.

* Similarly, under 'Options' in Proxy section, we can enable 'And URL is in target scope' for both 'Intercept Client Requests' and 'Intercept Server Responses' for granular control.

* The scoreboard for OWASP Juice shop can be found at <http://localhost:3000/#/score-board>
