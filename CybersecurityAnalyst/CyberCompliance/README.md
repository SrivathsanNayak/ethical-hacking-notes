# Cybersecurity Compliance Framework & System Administration

1. [Compliance Frameworks and Industry Standards](#compliance-frameworks-and-industry-standards)
2. [Client System Administration, Endpoint Protection and Patching](#client-system-administration-endpoint-protection-and-patching)
3. [Server and User Administration](#server-and-user-administration)
4. [Cryptography and Compliance Pitfalls](#cryptography-and-compliance-pitfalls)

## Compliance Frameworks and Industry Standards

* Security - designed protection from theft/damage, disruption or misdirection; physical, technical and operational controls.

* Privacy - based on how info is used/shared.

* Compliance - tests if security measures are in place; covers non-security requirements as well.

* Compliance types:

  * Foundational - general specifications; important but not legally required (e.g. - SOC, ISO).

  * Industry - specific to an industry; legal requirements (e.g. - HIPAA, PCI-DSS).

* General compliance process phases:

  * Establish scope
  * Readiness assessment
  * Gap remediation
  * Testing/Auditing
  * Management assertion & reporting
  * Re-Certify

* GDPR (General Data Protection Regulation):

  * Rights of EU Data Subjects
  * Security of Personal Data
  * Consent
  * Accountability of Compliance
  * Data Protection by Design and by Default

* ISO (International Organization for Standardization) 2700x - family of standards to help organizations keep info assets secure.

* HIPAA (Health Insurance Portability and Accountability Act) - US Federal laws and regulations that define control of most personal healthcare information (PHI) for companies responsible for managing such data.

* PCI-DSS (Payment Card Industry Data Security Standard) - applies to all entities that store, process and/or transmit cardholder data; covers technical and operational practices for system components.

* CIS (Center for Internet Security) Critical Security Controls - prioritized set of actions and best-practices that mitigate common attacks against systems & networks; includes basic, foundational and organizational control.

## Client System Administration, Endpoint Protection and Patching

* Common endpoint attacks:

  * Spear-phishing - email imitating a trusted source designed to target a specific person or department.

  * Watering hole - malware placed on a site frequently visited by employees.

  * Ad network attacks - using ad networks to place malware on machine through ad software.

  * Island hopping - supply chain infiltration.

* Endpoint protection management - policy-based approach to network security that requires endpoint devices to comply with criteria before accessing network resources.

* UEM (Unified Endpoint Management) - platform that converges client-based management with MDM (Mobile Device Management) APIs.

* EDR (Endpoint Detection and Response):

  * Automatic policy creation for endpoints
  * Zero-day OS updates
  * Continuous monitoring, patching and enforcement of security policies across endpoints

* Factors for endpoint security solution:

  * threat hunting
  * detection response
  * user education

* Patch - set of changes to a computer program, designed to update/fix/improve it; includes fixing security vulnerabilities and bugs.

* Types of Windows Patching:

  * Security updates
  * Critical updates
  * Software updates
  * Service packs

## Server and User Administration

* Windows Access Control:

  * After an user is authenticated, the OS determines if user has correct permissions to access a resource.

  * In access control model, users & groups (Security Principals) have assigned permissions.

  * Shared resources use ACLs (Access Control Lists) to assign permissions.

  * Privileged accounts such as Administrators have direct/indirect access to most assets.

* Default local user accounts:

  * Administrator
  * Guest
  * HelpAssistant
  * Default

* Default local system accounts:

  * SYSTEM
  * NETWORK SERVICE
  * LOCAL SERVICE

* Security considerations for local user accounts:

  * Restrict local accounts with admin rights
  * Enfore local account restrictions for remote access
  * Deny network logon to all local admin accounts
  * Create unique passwords for local accounts with admin rights

* AD DS (Active Directory Domain Services) - stores info about objects on network and makes this info easy for admins and users to use; objects include shared resources; security integrated in AD via authentication, access control and policy-based administration.

* AD features:

  * Schema (set of rules)
  * Global catalog
  * Query & index mechanism
  * Replication service

* Default local accounts in AD:

  * Administrator
  * Guest
  * HelpAssistant
  * KRBTGT

* Security considerations for AD accounts:

  * Manage default local accounts in AD
  * Secure and manage DC (Domain Controllers)
  * Separate admin accounts from user accounts
  * Create dedicated workstation hosts without Internet and email access
  * Restrict admin logon access to servers & workstations
  * Disable account delegation right for admin accounts

* Administrative responsibilities in AD:

  * Service administrators
  * Data administrators

* Types of groups in AD:

  * Distribution groups - to create email distribution lists.

  * Security groups - to assign permissions to shared resources.

* Group scopes in AD:

  * Universal
  * Global
  * Domain local

* Kerberos Authentication - protocol used to verify identity of user/host; Kerberos Key Distribution Center (KDC) is integrated with other Windows Server security services and uses AD DS database.

* Benefits of using Kerberos:

  * Delegated authentication
  * SSO (Single Sign On)
  * Interoperability
  * Efficient authentication
  * Mutual authentication

* Types of events that can be audited in Event Viewer:

  * Account logon events
  * Account management
  * Directory service access
  * Logon events
  * Object access
  * Policy change
  * Privilege use
  * Process tracking
  * System events

* Types of Linux commands:

  * Internal commands - built-in commands, shell-dependent; can be checked using 'type' command.

  * External commands - commands that the system offers, shell-independent; mostly found in /bin and /usr/bin.

## Cryptography and Compliance Pitfalls
