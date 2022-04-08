# OhSINT - Easy

* We are given an image, and using OSINT, we have to answer some questions.

1. What is the users avatar of?

```markdown
We can start off by viewing some metadata
Command: identify -verbose WindowsXP.jpg

This gives us a lot of useful info, including GPS coordinates
xmp:GPSLatitude: 54,17.687778N
xmp:GPSLongitude: 2,15.022104W

Alternatively, we can use exiftool as well
Command: exiftool WindowsXP.jpg

This gives us a few more details
Copyright: OWoodflint
GPS Position: 54 deg 17' 41.27" N, 2 deg 15' 1.33" W

Looking up the name 'OWoodflint' on Google, we get a Twitter account with a cat pfp, which gives us the answer for the first one
```

2. What city is the person in?

```markdown
The top Google searches also contain a link to his GitHub profile, which contains the name of his city.
```

3. Whats the SSID of the wap he connected to?

```markdown
The Twitter account also has his BSSID: B4:5D:50:AA:86:41
With the help of online tools, we can find his SSID as well.
SSID: UnileverWifi
```

4. What is his personal email address?

```markdown
This is also included in OWoodFlint's GitHub profile.
```

5. What site did you find his email address on?

```markdown
GitHub
```

6. Where has he gone on holiday?

```markdown
The search results also give his blog link, where he has stated that he has gone to New York.
```

7. What is this persons password?

```markdown
We can view the password in the page source of the blog.
Password: pennYDr0pper.!
```
