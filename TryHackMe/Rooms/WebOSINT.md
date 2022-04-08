# WebOSINT - Easy

* We have to find as much as information as possible about the website RepublicOfKoffee.com, which does not exist.

* We can search it up with quotes, so that the search engine does not redirect us to the URL.

* The most basic form of domain recon is a 'whois' lookup. An example for such a service is <https://lookup.icann.org/lookup>

---

1. What is the name of the company the domain was registered with? - NAMECHEAP INC

2. What phone number is listed for the registration company? - 6613102107

3. What is the first nameserver listed for the site? - dns1.registrar-servers.com

4. What is listed for the name of the registrant? - redacted for privacy

5. What country is listed for the registrant? - Panama

---

* We can use archive.org to see snapshots of our target domain.

---

1. What is the first name of the blog's author? - Steve

2. What city and country was the author writing from? - Gwangju, South Korea

3. What is the name of the temple inside the National Park the author frequently visits? - Jeungsimsa temple

---

* For DNS lookups, we can use websites such as <https://viewdns.info/>

---

1. What was RepublicOfKoffee.com's IP address as of October 2016? - 173.248.188.152

2. Based on the other domains hosted on the same IP address, what kind of hosting service can we safely assume our target uses? - shared

3. How many times has the IP address changed in the history of the domain? - 4

---

* Now, we have to use OSINT to find details about the domain "heat.net"

---

1. What is the second nameserver listed for the domain? - ns2.heat.net

2. What IP address was the domain listed on as of December 2011? - 72.52.192.240

3. Based on domains that share the same IP, what kind of hosting service is the domain owner using? - shared

4. On what date did was the site first captured by the internet archive? - 06/01/97

5. What is the first sentence of the first body paragraph from the final capture of 2001? - After years of great online gaming, it’s time to say good-bye.

6. Using your search engine skills, what was the name of the company that was responsible for the original version of the site? - SegaSoft

7. What does the first header on the site on the last capture of 2010 say? - Heat.net - heating and cooling

---

* In order to analyze websites and find more clues, we can look into the page source of the website.

* For quick wins, we can search for terms such as <!--> (comment), @ (email), .jpg (or other file extensions).

* We can use websites such as <https://www.nerdydata.com> to check if a particular code has been used in any other website or not.

---

1. How many internal links are in the text of the article? - 5

2. How many external links are in the text of the article? - 1

3. Website in the article's only external link - purchase.org

4. Try to find the Google Analytics code linked to the site - UA-251372-24

5. Is the the Google Analytics code in use on another website? Yay or nay

6. Does the link to this website have any obvious affiliate codes embedded with it? Yay or Nay - nay

---

* Now, we have to find the link between heat.net and purchase.org, as to why both these websites are connected.

* We can use the ViewDNS website we used earlier to research into this.

* When we check the IP history of both websites, we can see that both had the same owner, Liquid Web.

---

1. Use the tools to confirm the link between the two sites. - Liquid Web, L.L.C

---
