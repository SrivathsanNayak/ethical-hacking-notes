# AV Evasion: Shellcode - Medium

1. [Challenge](#challenge)
2. [PE Structure](#pe-structure)
3. [Introduction to Shellcode](#introduction-to-shellcode)
4. [Generate Shellcode](#generate-shellcode)
5. [Staged Payloads](#staged-payloads)
6. [Introduction to Encoding and Encryption](#introduction-to-encoding-and-encryption)
7. [Shellcode Encoding and Encryption](#shellcode-encoding-and-encryption)
8. [Packers](#packers)
9. [Binders](#binders)

## Challenge

```markdown
1. Which Antivirus software is running on the VM?

2. What is the name of the user account to which you have access?

3. Establish a working shell on the victim machine and read the file on the user's desktop. What is the flag?
```

## PE Structure

```markdown
1. What is the last 6 digits of the MD5 hash value of the thm-intro2PE.exe file?

2. What is the Magic number value of the thm-intro2PE.exe file (in Hex)?

3. What is the Entry Point value of the thm-intro2PE.exe file?

4. How many Sections does the thm-intro2PE.exe file have?

5. What is the name of the extra section?

6. Check the content of the extra section. What is the flag?
```

## Introduction to Shellcode

```markdown
1. Modify your C program to execute the following shellcode. What is the flag?
```

## Generate Shellcode

## Staged Payloads

```markdown
1. Do staged payloads deliver the full content of our payload in a single package?

2. Is the Metasploit payload windows/x64/meterpreter_reverse_https a staged payload?

3. Is the stage0 of a staged payload in charge of downloading the final payload to be executed?
```

## Introduction to Encoding and Encryption

```markdown
1. Is encoding shellcode only enough to evade Antivirus software?

2. Do encoding techniques use a key to encode strings or files?

3. Do encryption algorithms use a key to encrypt strings or files?
```

## Shellcode Encoding and Encryption

## Packers

```markdown
1. Will packers help you obfuscate your malicious code to bypass AV solutions?

2. Will packers often unpack the original code in-memory before running it?

3. Are some packers detected as malicious by some AV solutions?
```

## Binders

```markdown
1. Will a binder help with bypassing AV solutions?

2. Can a binder be used to make a payload appear as a legitimate executable?
```
