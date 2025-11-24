# Easy Phish - Easy

* given scenario - customers of 'secure-startup.com' have been receiving phishing emails, and we need to find the reason

* checking the domain:

    ```sh
    dig any secure-startup.com
    # this checks for available DNS records
    ```

* in the response, we can see a TXT record with a partial flag 'HTB{RIP_SPF_Always_2nd'

* it also includes the following SPF record - ```v=spf1 a mx ?all```

* this means that mail from the domain is authorized if it comes from IPs specified by the domain's ```A``` records, IPs of domain's ```MX``` records, or any other IP (which should be treated as suspicious)

* check for DNS zone transfer:

    ```sh
    dig axfr @15.197.148.33 secure-startup.com
    # this does not work
    # tested with other IPs and domains from previous output
    ```

* we can also check each step in the resolution path:

    ```sh
    dig +trace secure-startup.com
    ```

* Googling further, we find that similar to SPF, we have DKIM and DMARC as well - which are used in email authentication & phishing protection - and we can check these records:

    ```sh
    dig _dmarc.secure-startup.com txt
    ```

* the response includes the second part of the flag - '_F1ddl3_2_DMARC}' - both can be combined to get the flag
