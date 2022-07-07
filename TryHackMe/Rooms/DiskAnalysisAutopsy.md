# Disk Analysis & Autopsy - Medium

* We can view the given case files in Autopsy using the ```Open Case``` option.

* The MD5 hash of the data source can be viewed in the ```File Metadata``` section.

* The computer name can be found in the ```Operating System Information``` view from the list.

* All the user accounts and their details can be viewed in ```Operating System User Account``` section.

* Google shows us that the IP address and MAC address can be found in a file named ```irunin.ini```, so we search for this file in Autopsy.

* To get the network cards, we have to view the Registry by going to the Application tab of Software, in the Operating System Information. The path is ```Microsoft > Windows NT > CurrentVersion > NetworkCards```.

* The Google Maps location to be found can be simply viewed under ```Web Bookmarks```.

* We can go through all the images in the ```Images/Videos``` tab and search for images with names in them.

* The first flag can be found by viewing the console history of PowerShell for all users. This will lead us to the second exploit which is a PowerShell script.

* The required hacktools can be found in Windows Defender's scan history.

* For the YARA file, we know that the extension is ```.yar```; searching for this term leads us to a YARA file for passwords, which can be Googled to find the author.

* The archive file to be found can be discovered by going through ```Recent Documents```, but I had to search in the Extensions filter and Downloads as well.

```markdown
1. What is the MD5 hash of the E01 image? - 3f08c518adb3b5c1359849657a9b2079

2. What is the computer account name? - DESKTOP-0R59DJ3

3. List all the user accounts. - H4S4N, joshwa, keshav, sandhya, shreya, sivapriya, srini, suba

4. Who was the last user to log into the computer? - sivapriya

5. What was the IP address of the computer? - 192.168.130.216

6. What was the MAC address of the computer? - 08-00-27-2c-c4-b9

7. Name the network cards on this computer. - Intel(R) PRO/1000 MT Desktop Adapter

8. What is the name of the network monitoring tool? - Look@LAN

9. A user bookmarked a Google Maps location. What are the coordinates of the location? - 12°52'23.0"N 80°13'25.0"E

10. A user has his full name printed on his desktop wallpaper. What is the user's full name? - Anto Joshwa

11. A user had a file on her desktop. It had a flag but she changed the flag using PowerShell. What was the first flag? - flag{HarleyQuinnForQueen}

12. The same user found an exploit to escalate privileges on the computer. What was the message to the device owner? - flag{I-Hacked-You}

13. 2 hack tools focused on passwords were found in the system. What are the names of these tools? - lazagne, mimikatz

14. There is a YARA file on the computer. Inspect the file. What is the name of the author? - Benjamin DELPY gentilkiwi

15. One of the users wanted to exploit a domain controller with an MS-NRPC based exploit. What is the filename of the archive that you found? - 2.2.0 20200918 Zerologon encrypted.zip
```
