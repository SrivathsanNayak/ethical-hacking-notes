# Cybersecurity Roles, Processes & Operating System Security

1. [People Process & Technology](#people-process--technology)
2. [Examples & Princples of the CIA Triad](#examples--princples-of-the-cia-triad)
3. [Authentication and Access Control](#authentication-and-access-control)
4. [Windows Operating System Security Basics](#windows-operating-system-security-basics)
5. [Linux Operating System Security Basics](#linux-operating-system-security-basics)
6. [Overview of Virtualization](#overview-of-virtualization)

## People Process & Technology

* IT Security - protection of computer systems from theft/damage to hardware, software or information, as well as from disruption of services provided.

* Security standards and compliance:

  * Best practices, baselines and frameworks
  * Normative and compliance

* Roles in information security:

  * CISO (Chief Information Security Officer)
  * Information Security Architect
  * Information Security Consultant
  * Information Security Analyst
  * Information Security Auditor
  * Security Software Developer
  * Penetration Tester

* Security Operations Centers (SOC) need to have current skills, tools and processes for detecting, investigating and stopping threats.

* Process - set of defined steps that take inputs, add value, and produce outputs that satisfy a customer's requirements.

* Attributes of a process:

  * Inputs
  * Outputs
  * Scope
  * Tasks

* CPI (Continual Process Improvement) - regular review of:

  * Process metrics
  * Customer feedback
  * Maturity assessments
  * Financial performance

* ITIL (IT Infrastructure Library) - best practice framework describing how IT resources should be organized to deliver business value.

* ITIL service lifecycle phases:

  * Strategy
  * Design
  * Transition
  * Operations
  * Improvement

* Key ITIL processes:

  * Problem Management
  * Change Management
  * Incident Management
  * Event Management
  * Service Level Management
  * Information Security Management

## Examples & Princples of the CIA Triad

* Key objectives of network security:

  * Confidentiality
  * Integrity
  * Availability
  * Authenticity
  * Accountability

## Authentication and Access Control

* Identification and AAA - Authentication, Authorization, Accountability

* Control types - Administrative, Technical and Physical

* Each control type can be:

  * Corrective
  * Preventive
  * Dissuasive
  * Recovery
  * Detective
  * Compensatory

* Access control models:

  * MAC (Mandatory Access Control) - use labels to regulate access; military use.

  * DAC (Discretionary Access Control) - each object (file/folder) has an owner, who defines the privilege.

  * RBAC (Role Based Access Control) - rights configured based on user roles.

  * Centralized - SSO (Single Sign on); AAA.

  * Decentralized - independent access control methods; local power.

* Best practices for access control:

  * Least privilege
  * Separation of duties
  * Rotation of duties

* Physical access control methods:

  * Perimetral
  * Building
  * Work areas
  * Servers and networks

* Monitoring the access control process:

  * IDS
  * IPS
  * Host IDS and IPS
  * HoneyPot
  * Sniffers

## Windows Operating System Security Basics

* Windows components:

  * User Mode:

    * When an application is started in user-mode, Windows creates a process for the application.

    * Each application runs in isolation (private virtual address space and private handle table); if app crashes, it is limited to that one app.

  * Kernel Mode:

    * All code that runs in kernel-mode shares a single virtual address space.

    * If kernel-mode driver accidentally writes to the wrong virtual address, data could be compromised.

    * If kernel-mode driver crashes, entire OS crashes.

* File system - enables apps to store & retrieve files on storage devices; files are placed in a hierarchical structure.

* Types of file systems:

  * NTFS (New Technology File System) - most common file system for Windows end user systems.

  * FATxx (File Allocation Table) - numbers preceding FAT refer to number of bits used to enumerate a file system block; used for removable storage devices.

## Linux Operating System Security Basics

* Linux components:

  * Kernel:

    * Core of OS; interacts directly with hardware.

    * Manages system and user I/O.

  * Shell:

    * Used to interact with kernel.

    * User input commands through shell; kernel performs the commands

* File system:

  * /:

    * Every single file & directory starts from / (root directory).

    * Only root user has write privileges in this directory.

    * / is not same as /root, which is the home directory of root.

  * /bin:

    * Contains binary executables.

    * Common linux commands are found here.

  * /sbin:

    * Contains binary executables, more related to system maintenance.

  * /etc:

    * Contains config files required by all programs.

  * /var:

    * Contains files expected to grow/change constantly.

    * Application logs usually found in /var/log.

  * /tmp:

    * Contains temporary files; deleted when system reboots.

  * /home:

    * Home directories for all users are located here; for personal files.

  * /boot:

    * Contains boot loaded files, used at boot time.

* Run levels:

  * 0 - Halt - shuts down all services when system will not be rebooted.

  * 1 - Single User - used for system maintenance; no network capabilities.

  * 2 - Multi User - used for maintenance and system testing; no network support.

  * 3 - Multi User with Network Support - Non-graphical, text mode operations for server systems.

  * 4 - Undefined - Custom Mode, used by SysAdmin.

  * 5 - Graphical - Graphical login, with same usability of Run Level 3.

  * 6 - Reboot - shuts down all services when system is rebooted.

* In Linux, there are 3 entities that can 'own' a file - user, group, everybody.

* There are 3 types of permissions - Read(r), Write(w), Execute(x).

## Overview of Virtualization
