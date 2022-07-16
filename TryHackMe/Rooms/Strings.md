# MAL: Strings - Easy

1. [What are "strings"](#what-are-strings)
2. [Practical: Extracting "strings" from an Application](#practical-extracting-strings-from-an-application)
3. [Strings in the Context of Malware](#strings-in-the-context-of-malware)
4. [Practical: Finding Bitcoin Addresses in Ransomware](#practical-finding-bitcoin-addresses-in-ransomware)
5. [Summary](#summary)

## What are "strings"

```markdown
1. What is the name of the account that had the passcode of "12345678" in the intellian example? - intellian

2. What is the CVE entry disclosed by the company "Teradata" in their "Viewpoint" Application that has a password within a string? - CVE-2019-6499

3. According to OWASP's list of "Top Ten IoT" vulnerabilities, name the ranking this vulnerability would fall within, represented as text. - one
```

## Practical: Extracting "strings" from an Application

```shell
strings ~/Downloads/LoginForm.exe > LoginFormStrings.txt

vim LoginFormStrings.txt
```

```markdown
1. What is the correct username required by the "LoginForm"? - cmnatic

2. What is the required password to authenticate with? - TryHackMeMerchWhen

3. What is the "hidden" THM{} flag? - THM{Not_So_Hidden_Flag}
```

## Strings in the Context of Malware

```markdown
1. What is the key term to describe a server that Botnets recieve instructions from? - Command and Control

2. Name the discussed example malware that uses "strings" to store the bitcoin wallet addresses for payment - Wannacry
```

## Practical: Finding Bitcoin Addresses in Ransomware

```markdown
1. List the number of total transactions that the Bitcoin wallet used by the "Wannacry" author(s) - 143

2. What is the Bitcoin Address stored within "ComplexCalculator.exe" - 1LVB65imeojrgC3JPZGBwWhK1BdVZ2vYNC
```

## Summary

```markdown
1. What is the name of the toolset provided by Microsoft that allows you to extract the "strings" of an application? - Sysinternals

2. What operator would you use to "pipe" or store the output of the strings command? - >

3. What is the name of the currency that ransomware often uses for payment? - Bitcoin
```
