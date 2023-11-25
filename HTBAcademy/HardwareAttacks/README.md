# Brief Intro to Hardware Attacks

1. [Bluetooth Attacks](#bluetooth-attacks)
1. [Cryptanalysis Side-Channel Attacks](#cryptanalysis-side-channel-attacks)
1. [Microprocessor Vulnerabilities](#microprocessor-vulnerabilities)

## Bluetooth Attacks

* Bluetooth - wireless technology standard for transferring data over short distances.

* It establishes PAN (personal area networks) using radio frequencies in ISM band from 2.402 - 2.480 GHz.

* Steps in establishing connection include Discovery, Pairing Request, Authentication (uses link key or long-term key).

* Once devices are paired, they remember details and can automatically connect without going through the pairing process again.

* After pairing, Bluetooth devices form a network called piconet - consists of one main device & upto 7 active clients; multiple piconets can interact to form a larger network called scatternet.

* Bluetooth connections facilitate both data & audio communication.

* Bluetooth specification identifies 2 types of links for data transfer -

  * SCO (Synchronous Connection-Oriented) links - primarily used for audio communication; reserve slots at regular intervals for data transmission for steady data flow

  * ACL (Asynchronous Connection-Less) links - for transmitting all other data types; don't reserve slots but transmit data whenever bandwidth allows

* Risks of Bluetooth:

  * Unauthorized access
  * Data theft
  * Interference
  * Denial of Service (DoS)
  * Device tracking

* Bluetooth attacks:

  * Bluejacking - sending unsolicited messages to device

  * Bluesnarfing - unauthorized access to device data

  * Bluebugging - remotely controlling Bluetooth device

  * Car whisperer - targets & remotely controls vehicles

  * Bluesmacking & DoS - disrupt connection between Bluetooth devices

  * MITM - attacker positioned between communicating devices

  * BlueBorne - to take control of device without requiring any user interaction or device pairing

  * Key Extraction - retrieve encryption keys used in Bluetooth connections

  * Eavesdropping - intercepting & listening to communications

  * Bluetooth Impersonation attack - impersonate a trusted Bluetooth device to gain unauthorized access

* Legacy attacks include Bluejacking, Bluesnarfing, Bluebugging and Bluesmacking; modern attacks include BlueBorne, KNOB (Key Negotiation of Bluetooth), and impersonation attacks.

* Mitigation:

  * keep devices updated
  * disable Bluetooth when not needed
  * enable device pairing authorization
  * limit device visibility
  * exercise caution in public

## Cryptanalysis Side-Channel Attacks

* Cryptanalysis - process of decrypting encrypted data without accessing the key; used to assess strength of encryption techniques.

* Cryptanalysis uses many techniques to break a cryptographic system, including frequency analysis, pattern finding & bruteforce attacks.

* Cryptanalysis side-channel attacks refer to a category of cryptographic attacks that exploit info leaked during execution of cryptographic algorithms.

* Rather than identifying flaws in algorithms, side-channel attacks aim at physical implementation, leveraging indirect info like timing data, power usage, signals, etc.

* 2 types of side-channel attacks:

  * Passive side-channel attacks - attacker monitors system without actively interfering; data leakage stems from system's natural functioning
  * Active side-channel attacks - attacker manipulates system to provoke informative changes

* Timing attacks:

  * attacker gains info based on amount of time the system takes to process different inputs
  * measure computation time and make informed guesses about secret key based on observed variations
  * mitigation of timing attacks involves use of constant-time algorithms

* Power-monitoring attacks:

  * power analysis attacks; exploit variations in device's power consumption to extract info
  * power usage measured from device's power line; then advanced statistical methods used to analyze power traces and extract secret keys
  * 2 types of power-monitoring attacks - SPA (simple power analysis) and DPA (differential power analysis)

* Acoustic cryptanalysis:

  * extracting sensitive info by analyzing sound emissions, which correlate with different internal states or operations
  * mitigation involves measures like using sound-absorbing materials in hardware and avoiding recognisable sound patterns

## Microprocessor Vulnerabilities

* Microprocessor - IC (integrated circuit) that encapsulates functions of a CPU on a single silicon chip

* Functional architecture of a microprocessor involves around several components like CU (control unit), ALU (arithmetic logic unit) and ISA (instruction set architecture).

* In the fetch-decode-execute cycle of microprocessors, transistors function to store & manipulate binary data during instruction execution.

* Stages of microprocessor design include architectural design, logic design, circuit design, physical design & verification.

* Microprocessor optimization strategies include pipelining, speculative execution and caching.

* Spectre:

  * class of microprocessor vulnerabilities; officially known as CVE-2017-5753 (bounds check bypass, Spectre-V1) & CVE-2017-5715 (branch target injection, Spectre-V2)
  * takes advantage of speculative execution used in modern microprocessors

* Meltdown:

  * officially known as CVE-2017-5754
  * severe microprocessor vulnerability disclosed along with Spectre
  * unlike Spectre, which breaks the isolation between different apps, Meltdown dissolves fundamental isolation between user apps and OS
  * exploits out-of-order execution feature of modern microprocessors

* Mitigation strategies:

  * Retpoline:
  
    * mitigation technique for Spectre
    * replacing potentially hazardous indirect software branches prevents speculative exploitation
    * indirect software branch - type of program instruction that guides the execution path based on specific conditions; it is dynamic
  
  * Compiler barriers:

    * mitigation technique for Spectre
    * introduces specific code instructions called barriers
    * memory barriers (or fence instructions) - ensure all load & store memory operations before barrier are completed before any operations after barrier
    * branch prediction barriers - to inhibit speculative execution at certain points in code
  
  * KPTI:

    * primary mitigation for Meltdown
    * isolates kernel's page table from pages tables of user space processes
  
  * Microcode updates:

    * to enable CPUs to implement fine-grained control & restrictions on speculative execution
    * allows OS to apply strict measures and prevent exploitation of vulnerabilities like Meltdown
