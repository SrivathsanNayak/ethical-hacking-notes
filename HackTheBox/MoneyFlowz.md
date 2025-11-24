# Money Flowz - Easy

* given scenario - we are given a name Frank Vitalik, and we have to find out where the money flows

* Googling for this name shows a Reddit account for user 'frankvitalik'

* the profile description mentions 'cryptocurrency enthusiast', and also includes their twitter ID with the same account name

* this Reddit account has a few posts, but the oldest post leads to a link - 'https://steemit.com/htb/@freecoinz/freecoinz'

* this mentions a scam crypto giveaway, and mentions an Ethereum address

* using [etherscan.io](https://etherscan.io/), we can check for more info on this particular address

* this Ethereum address has no transactions or activity linked to it

* going back to the 'steemit' post, the post includes a comment by the author 'freecoinz' - this mentions 'ropsten net'

* Googling about this shows that it is meant as a test framework and is now deprecated

* we can use the Etherscan explorers for different testnets; in this case, as we want to check on ropsten testnet, we need to navigate to [ropsten.etherscan.io](https://ropsten.etherscan.io)

* the webpage does not load and it seems it was discontinued so we need to check on alternative websites

* we find a webpage for Trezor, an Ethereum Ropsten Explorer, and we can lookup the Ethereum address here

* this shows a lot of transactions - we can start checking the older transactions first

* in the second oldest transaction with transaction ID '0xe1320c23f292e52090e423e5cdb7b4b10d3c70a8d1b947dff25ae892609f2ef4', we see the input field is non-empty and contains some data

* if we decode the data in Cyberchef, it decodes it from hex and we get the flag "HTB{CryPt0Curr3ncy_1s_FuNz!!}"
