# Network Operations

## Network Documentation

* Documenting network:

    1. Mapping the network - logical and physical network maps
    2. Change management
    3. Managing cables
    4. System labeling
    5. Circuit labeling
    6. Patch panel labeling
    7. Baselines - point of reference
    8. Inventory management

## Business Continuity

* Fault tolerance - maintain uptime in case of failure; adds complexity and cost.

* Single device fault tolerance - RAID, redundant power supplies and redundant NICs.

* Multiple device fault tolerance - server farms with load balancing and multiple network paths.

* Redundancy and fault tolerance - redundant hardware components, RAID, UPS, clustering and load balancing.

* High availability (HA) - includes many different components working together; higher costs.

* NIC teaming - LBFO (Load Balancing/Fail Over); multiple network adapters; port aggregation; fault tolerance.

* UPS (Uninterruptible Power Supply) - short-term backup power; can be offline, line-interactive or online.

* Generators - long-term power backup; power an entire building

* Dual-power supplies - redundant; hot-swappable.

* Recovery sites:

    1. Cold site - no hardware, data, people.
    2. Warm site - only hardware available.
    3. Hot site - exact replica; stocked with hardware, updated.

* Full backups - all selected data backup; takes a lot of time.

* Incremental backups - all files changed since last incremental backup.

* Differential backups - all files changed since the last full backup.

* Snapshots - capture current configuration and data in cloud; revert to known state or rollback to known configuration.

## Network Monitoring

* Process monitoring:

    1. Log management
    2. Data graphing
    3. Port scanning
    4. Vulnerability scanning
    5. Patch management
    6. Baseline review
    7. Protocol analyzers

* Event management:

    1. Interface monitoring
    2. SIEM (Security Information and Event Management)
    3. Syslog
    4. SNMP (Simple Network Management Protocol)

## Remote Access

* Remote access protocols:

    1. IPSec (IP Security) - security for OSI layer 3; confidentiality, integrity, standardized; AH (Authentication Header) and ESP (Encapsulation Security Payload).
    2. Site-to-Site VPNs - encrypt traffic between sites through public Internet.
    3. SSL VPN (Secure Sockets Layer VPN) - uses SSL/TLS protocol (tcp/443); authenticate users.
    4. Client-to-Site VPNs - remote access VPN.
    5. DTLS VPN (Datagram Transport Layer Security VPN) - transport using UDP instead of TCP.
    6. Remote desktop access - RDP (Microsoft Remote Desktop Protocol), VNC (Virtual Network Computing).
    7. SSH (Secure Shell) - encrypted console communication (tcp/22).
    8. File transferring - FTP (File Transfer Protocol), FTPS (FTP over SSL), SFTP (SSH FTP), TFTP (Trivial FTP).
