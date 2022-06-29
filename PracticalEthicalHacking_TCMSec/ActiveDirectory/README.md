# Active Directory

1. [Introduction](#introduction)

## Introduction

* Active Directory (AD) - Directory service developed by Microsoft to manage Windows domain networks; authenticates using Kerberos tickets.

* Physical AD components:

  * Domain Controller - server with AD DS (Active Directory Domain Services) server role installed; hosts a copy of the AD DS directory store and provides authentication & authorization services; admin access.

  * AD DS Data Store - contains database files and processes that store, manage directory info for users, services, apps; consists of Ntds.dit file.

* Logical AD components:

  * AD DS Schema - enforces rules regarding object creation and configuration.

  * Domains - used to group and manage objects in an organization.

  * Trees - hierarchy of domains in AD DS.

  * Forests - collection of domain trees.

  * Organizational Units (OUs) - AD containers that can contain users, groups, containers and other OUs.

  * Trusts - mechanism for users to gain access to resources in another domain; can be directional or transitive.

  * Objects - user, groups, contacts, computers, etc.; everything inside a domain.
