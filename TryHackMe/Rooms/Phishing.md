# Phishing - Medium

1. [Intro](#intro)
2. [Writing Convincing Phishing Emails](#writing-convincing-phishing-emails)
3. [Phishing Infrastructure](#phishing-infrastructure)
4. [Using GoPhish](#using-gophish)
5. [Droppers](#droppers)
6. [Choosing a Phishing Domain](#choosing-a-phishing-domain)
7. [Using MS Office in Phishing](#using-ms-office-in-phishing)
8. [Using Browser Exploits](#using-browser-exploits)
9. [Phishing Practical](#phishing-practical)

## Intro

* Social engineering - psychological manipulation of people into giving info by exploiting weaknesses in human nature.

* Phishing - social engineering delivered through mail.

* Spear-phishing - phishing a single entity.

* Smishing - phishing through SMS messages.

* Vishing - phishing through phone calls.

```markdown
1. What type of psychological manipulation is phishing part of? - Social engineering

2. What type of phishing campaigns do red teams get involved in? - Spear-phishing
```

## Writing Convincing Phishing Emails

* Sender's address - domain name that spoofs a significant brand, a known contact or a coworker.

* Subject - something urgent, worrying or interesting.

* Content - learn and research standard email templates and branding of the entity who is being impersonated.

```markdown
1. What tactic can be used to find brands or people a victim interacts with? - OSINT

2. What should be changed on an HTML anchor tag to disguise a link? - Anchor text
```

## Phishing Infrastructure

* Infrastructure required for phishing campaign:

  * Domain name
  * SSL/TLS certificates
  * Email server/account
  * DNS records
  * Web server
  * Analytics

* Automation tools for infrastructure:

  * GoPhish
  * Social Engineering Toolkit

```markdown
1. What part of a red team infrastructure can make a website look more authentic? - SSL/TLS certificates

2. What protocol has TXT records that can improve email deliverability? - DNS

3. What tool can automate a phishing campaign and include analytics? - GoPhish
```

## Using GoPhish

* Sending profiles - connection details required to send phishing emails.

* Landing page - website that the phishing email is going to direct the victim to.

* Email Templates - design & content of email to be sent to victim.

* Users & Groups - store email addresses of intended targets.

```markdown
1. What is the password for Brian? - p4$$w0rd!
```

## Droppers

* Droppers - software that phishing victims tend to be tricked into downloading and running on their system; droppers are not malicious, they aid in unpacking or downloading malware.

```markdown
1. Do droppers tend to be malicious? - nay
```

## Choosing a Phishing Domain

* Methods for choosing a phishing domain name:

  * Expired domains

  * Typosquatting

  * TLD alternatives

  * IDN homograph attack (script spoofing)

```markdown
1. What is better, using an expired or new domain? - old

2. What is the term used to describe registering a similar domain name with a spelling error? - Typosquatting
```

## Using MS Office in Phishing

* MS Office documents with macros can be included as attachments; this can aid in installing malware.

```markdown
1. What can Microsoft Office documents contain, which, when executed can run computer commands? - Macros
```

## Using Browser Exploits

* Browser exploits can be used in gaining control over a victim's computer.

```markdown
1. Which recent CVE caused remote code execution? - CVE-2021-40444
```

## Phishing Practical

```markdown
1. What is the flag from the challenge? - THM{I_CAUGHT_ALL_THE_PHISH}
```
