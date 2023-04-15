# DAST - Medium

1. [Introduction](#introduction)
2. [Spiders and Crawlers](#spiders-and-crawlers)
3. [Scanning for Vulnerabilities](#scanning-for-vulnerabilities)
4. [Authenticated Scans](#authenticated-scans)
5. [Checking APIs with ZAP](#checking-apis-with-zap)
6. [Integrating DAST into the development pipeline](#integrating-dast-into-the-development-pipeline)

## Introduction

```markdown
1. Is DAST a replacement for SAST or SCA?

2. What is the process of mapping an application's surface and parameters usually called?

3. Does DAST check the code of an application for vulnerabilities?
```

## Spiders and Crawlers

```markdown
1. ZAP can run an AJAX spider by using browsers without a GUI. What are these browsers called?

2. Analysing the Sites tab, what HTTP parameters can be passed to login.php using the POST method?

3. What other .php resource, besides nospiders-gallery.php was found by the AJAX spider but not by the regular spider?
```

## Scanning for Vulnerabilities

```markdown
1. Will disabling some test categories help speed up the scanning phase?

2. There should be two high-risk alerts in your scan results. One is Path Traversal. What's the name of the other one?
```

## Authenticated Scans

```markdown
1. Which type of script was used to record the authentication process to our site in ZAP?

2. What additional high-risk vulnerability was found on the site after running the authenticated scan?
```

## Checking APIs with ZAP

```markdown
1. What high-risk vulnerability was found on the /asciiart/generate endpoint?

2. Based solely on the information presented by the scanner, would you categorise this finding as a false positive?
```

## Integrating DAST into the development pipeline

```markdown
1. Download the ZAP report for the simple-webapp repository. How many medium-risk vulnerabilities were found?

2. Check the main branch of the simple-api repository on Jenkins. One of the builds failed during the Build the Docker image step. What is the number of the pre-existing failed build?

3. Download the ZAP report for the simple-api repository. What high-risk vulnerability was found?
```
