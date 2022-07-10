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

## SECaaS Categories

## Domain 14 Considerations
