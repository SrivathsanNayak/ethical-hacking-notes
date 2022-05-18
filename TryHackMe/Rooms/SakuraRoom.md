# Sakura Room - Easy

1. [Tip-Off](#tip-off)
2. [Reconnaissance](#reconnaissance)
3. [Unveil](#unveil)
4. [Taunt](#taunt)
5. [Homebound](#homebound)

## Tip-Off

```markdown
The given svg file can be saved and analyzed using exiftool to reveal the username.

1. What username does the attacker go by? - SakuraSnowAngelAiko
```

## Reconnaissance

```markdown
We know that this username has been used on social media platforms.

Searching up this username gives us a GitHub profile and a LinkedIn profile.

The LinkedIn profile gives us the real name.

The GitHub profile contains multiple repos, one of them is PGP key repo.

Copying the PGP key and decoding it using Base64 gives us random text, which also contains the email address.

Command: echo "pasted PGP key" | base64 -d

1. What is the full email address used by the attacker? - SakuraSnowAngel83@protonmail.com

2. What is the attacker's full real name? - Aiko Abe
```

## Unveil

```markdown
We can further inspect the GitHub repo for cryptocurrency clues.

The commit history for the ETH repo includes the wallet address in question.

In order to check the transactions for the Ethereum wallet address, we can use websites such as [EtherScan](https://etherscan.io/).

Entering the wallet address there shows the complete list of transactions.

We can check the transaction which occurred on January 23, 2021 UTC.

Furthermore, we can see that the attacker exchanged another cryptocurrency as well.

1. What cryptocurrency does the attacker own a cryptocurrency wallet for? - Ethereum

2. What is the attacker's cryptocurrency wallet address? - 0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef

3. What mining pool did the attacker receive payments from on January 23, 2021 UTC? - Ethermine

4. What other cryptocurrency did the attacker exchange with using their cryptocurrency wallet? - Tether
```

## Taunt

```markdown
In the given Twitter screenshot, we know that the username is AikoAbe3.

Searching that username gives us the Twitter handle.

We can go through the Twitter posts to get clues for the saved WiFi credentials.

From one of the posts, we get the clue "DeepPaste".

Googling this tells us that this is a Dark Web version of Pastebin.

We can use Dark web search engines such as Ahmia to search for [DeepPaste](http://depasteon6cqgrykzrgya52xglohg5ovyuyhte3ll7hzix7h5ldfqsyd.onion).

On DeepPaste, we can simply use the search term (MD5 hash) seen in the screenshot and search.

This gives us the required DeepPaste.

Now, we have some data about the attacker's Home WiFi - DK1F-G:Fsdf324T@@

Searching for "wifi bssid lookup" gives us the link to [WiGLE](https://www.wigle.net/).

We can use the acquired data to get the Home WiFi's BSSID, using Advanced Search in the website.

1. What is the attacker's current Twitter handle? - SakuraLoverAiko

2. What is the URL for the location where the attacker saved their WiFi SSIDs and passwords? - http://depasteon6cqgrykzrgya52xglohg5ovyuyhte3ll7hzix7h5ldfqsyd.onion/show.php?md5=0a5c6e136a98a60b8a21643ce8c15a74

3. What is the BSSID for the attacker's Home WiFi? - 84:AF:EC:34:FC:F8
```

## Homebound

```markdown
We have to attempt to track the location using the photos shared on Twitter.

We have to reverse-search the images in order to get a better idea.

On reverse-searching the cherry blossom shared by the attacker before getting on flight, we do not get many clues.

We have to isolate each element and then reverse-search. This can be done in Yandex reverse image search by zooming onto the elements.

For the tower in the background, Yandex shows results for Washington Monument.

Searching for closest airports to Washington Monument, we get Ronald Reagan Washington National Airport (DCA).

On reverse-searching the Sakura Lounge image, we get results for the Haneda Aiport (HND).

On reverse-searching the map image, we know that it is the map for Fukushima.

Searching for lakes in Fukushima gives us the lake Inawashiro.

Now, in order to find the home city, we have to consider all clues we have.

We know that the flight is from Haneda Airport and it passes by Fukushima.

We can view the route in Google Maps and look for cities to the north of Lake Inawashiro.

We know that the city name consists of 8 letters, so we can attempt for the few cities north to Fukushima with an 8-letter long name.

This gives us the city of the attacker.

1. What airport is closest to the location the attacker shared a photo from prior to getting on their flight? - DCA

2. What airport did the attacker have their last layover in? - HND

3. What lake can be seen in the map shared by the attacker as they were on their final flight home? - Lake Inawashiro

4. What city does the attacker likely consider "home"? - Hirosaki
```
