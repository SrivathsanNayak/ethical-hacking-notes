# Unit42 - Very Easy

* given scenario - Sysmon logs have been captured for an UltraVNC campaign, in which attackers used a backdoored version of UltraVNC

* the given zip file includes the '.evtx' log file - we can use online EVTX viewers to read the file contents

* event ID 1 records the creation of a new process in memory; in this case, checking event ID 1 logs, we see a malicious process 'C:\Users\CyberJunkie\Downloads\Preventivo24.02.14.exe.exe'

* checking for the cloud drive used to distribute this malware, we can start by checking event ID 22 - which records DNS query events for DNS lookups by processes; in this case Dropbox is used

* it is mentioned that the malicious file used time stomping as an evasion technique (where file creation date is changed to an older timestamp) - we need to filter by event ID 2 to check this for the given PDF file

* the malicious file also creates a few files on disk (event ID 11), and tried to reach to a dummy domain (event ID 22)

* to check if malware tried to check for outbound connections, we can filter logs for event ID 3 - this shows the malware tried to reach out to a particular destination IP

* to check for events associated with process termination, we need to filter for event ID 5
