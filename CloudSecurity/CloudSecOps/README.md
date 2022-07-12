# Cloud Security Operations

1. [Selecting a Cloud Provider](#selecting-a-cloud-provider)
2. [Incident Response](#incident-response)
3. [SECaaS Fundamentals](#secaas-fundamentals)
4. [SECaaS Categories](#secaas-categories)
5. [Domain 14 Considerations](#domain-14-considerations)

## Selecting a Cloud Provider

* Characteristics to look for in a cloud provider:

  * Compartmentalization of job roles

  * Well-defined security policies

  * Reviewable audits

  * Ability to inspect/audit provider

  * Well-defined contractual language

  * Well-defined BC/DR policy

  * Configuration management process

  * Patch management process

  * Robust, well-documented API

  * Security in development and operations process

  * Prioritization of security

* Documentation to look for from a cloud provider:

  * Scope and time

  * Service coverage

  * Audit firm history

* Critical capabilities in cloud providers (IaaS & PaaS):

  * API access & admin monitoring

  * Elasticity & autoscaling

  * APIs for all security features

  * Good SAML support

  * Multiple accounts or projects

  * SDN (Software-defined networking)

  * Region control

  * Infra templating/automation

* Critical capabilities in cloud providers (SaaS):

  * Robust external security & compliance assessments

  * Granular IAM entitlements

  * Monitoring & logging of admin activity

  * External log feeds

  * Strong internal controls to limit admin access

* CSA tools - CCM, CAIQ, CSA STAR, STARwatch

## Incident Response

* Likelihood of incidents change frequently with the environment, the metastructure is the key difference.

* IR (Incident Response) Lifecycle:

  * Preparation - understand data, SLAs, contracts; architect for faster detection, investigation and remediation

  * Detection & Analysis - depends on data availability; impacted by lack of transparency to provider's infra

  * Containment, Eradication & Recovery - start with metastructure; software-defined infra can help with containment

  * Post-Mortem - pay attention to data source, metastructure response and communications with cloud provider

* IR recommendations:

  * SLAs and setting expectations for customer and provider responsibilities

  * Clear communication

  * Cloud customers must embrace monitoring of cloud-based resources

  * Automation and orchestration can accelerate the response

  * Incident handling should be planned beforehand

  * SLA must guarantee support for incident handling

  * Regular testing should be done

## SECaaS Fundamentals

* SECaaS (Security as a Service) - security product or service, with cloud-based management data; this can secure data and systems in cloud, in trad networks or hybrid environments.

* SECaaS Characteristics:

  * Security products or services delivered as a cloud service

  * Meets NIST essential characteristics

* SECaaS potential benefits:

  * Cloud computing benefits

  * Staffing & expertise

  * Intelligence sharing

  * Deployment flexibility

  * Insulation of clients

  * Scaling & costs

* SECaaS potential concerns:

  * Lack of visibility

  * Regulation differences

  * Handling of regulated data

  * Data leakage

  * Changing providers

  * Migrating to SECaaS

* The cloud consumer can never outsource their accountability.

## SECaaS Categories

* IAM services:

  * Federated Identity Brokers
  * Strong Authentication
  * Cloud-based directories

* CASBs (Cloud Access Security Brokers) - can be cloud-hosted; used to manage SaaS apps

* Web Security Gateways - delivered via cloud by proxying web traffic to provider; policy rules and allowed time frames for web access also enforced; protective, detective and reactive control

* Email Security - filter inbound & outbound email to block spam, phishing, malware, etc.; protects from email floods

* Security assessment:

  * Traditional vulnerability
  * Application security
  * Cloud platform assessment

* Web Application Firewalls (WAFs)

* Encryption & key management:

  * Cloud-based key management
  * Encryption/decryption via API & encrypted connections

* SIEM (Security Information and Event Management) - aggregate log and event data from networks, apps, systems, etc.; provide alerts based on mutually agreed rule set

* BC/DR - using cloud service to back up internal controls; needs sync and clear demarcation of accountability

* Other categories include DDoS protection, Security management, endpoint security (IDS)

* SECaaS recommendations:

  * Understand security-specific needs for data handling, investigative and compliance support

  * Pay attention to handling of regulated data

  * Understand data retention needs

  * Ensure the SECaaS service is compatible with current and future plans

## Domain 14 Considerations

* Related technologies - key technologies interrelated with cloud computing; for example, big data, IoT, etc.

* Big Data - high volume, high velocity, high variety; distributed data collection, storage and processing.

* Big Data cloud security:

  * Know your platform

  * Secure the platform

  * Securing all the storage

  * Encryption key management (BYOK)

* IoT security priorities:

  * APIs and Device authentication/authorization

  * Data collection

  * Encrypted communications

  * Device patching and updating

* Mobile & Cloud:

  * Most mobile apps connect to cloud

  * Device registration, authentication and authorization

  * Application APIs can expose cloud deployment

* Serverless includes PaaS and FaaS; IAM and logging are key security issues for serverless apps; more security benefits due to higher responsibility of cloud provider.
