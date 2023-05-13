# DAST - Medium

1. [Introduction](#introduction)
2. [Spiders and Crawlers](#spiders-and-crawlers)
3. [Scanning for Vulnerabilities](#scanning-for-vulnerabilities)
4. [Authenticated Scans](#authenticated-scans)
5. [Checking APIs with ZAP](#checking-apis-with-zap)
6. [Integrating DAST into the development pipeline](#integrating-dast-into-the-development-pipeline)

## Introduction

* DAST (Dynamic Application Security Testing) - testing a running instance of a web app for vulnerabilities by trying to exploit them, manually or through automation.

* DAST focuses on a black-box testing approach.

* It doesn't replace other methods to find vulnerabilities in apps, but rather complements them.

* Manual DAST - security engineer manually performs tests against app to check for vulnerabilities.

* Automatic DAST - automated tool will scan web app for vulnerabilities.

* Both processes are complementary and can be used at different stages of the SDLC (Software Development Lifecycle).

* DAST pros:

  * Finds vulnerabilities during runtime
  * Finds vulnerabilities like HTTP request smuggling, cache poisoning that won't be found using SAST
  * All apps treated in a language-agnostic way
  * Reduced number of false positives
  * DAST tools can find business logic flaws

* DAST cons:

  * Code coverage is not the best
  * Some vulnerabilities may be harder to find using DAST, compared to SAST
  * Some apps are difficult to be crawled
  * DAST scanners won't tell how to remediate some vulnerabilities in detail
  * Running app required for testing

* In general, a DAST tool (like ZAP proxy) will perform at least the following tasks against target website:

  * Spidering/Crawling - tool will navigate through web app, trying to map the app and identify list of pages & parameters that can be attacked

  * Vulnerability Scanning - tool will launch attack payloads against these pages & parameters

```markdown
1. Is DAST a replacement for SAST or SCA? - Nay

2. What is the process of mapping an application's surface and parameters usually called? - Spidering/Crawling

3. Does DAST check the code of an application for vulnerabilities? - Nay
```

## Spiders and Crawlers

* ZAP provides a spidering module under Tools -> Spider; a ```Spider``` will navigate to a starting page and fundamentally explore the website by following all the detected links.

* We can point the Spider to <http://10.10.35.153:8082> and start our scan - this shows all the URLs found by the Spider under the Sites tab.

* However, the Spider is unable to detect a link from the menu, ```/nospider-gallery.php``` - this is because this particular link is not directly embedded in the HTML code but generated on-the-fly by JS, and the regular spider does not have a JS engine.

* We can use ```AJAX Spider``` in ZAP which leverages a real browser to process any scripts attached to website.

* Under Tools -> AJAX Spider, we can configure the same URL as starting point and start our scan.

```markdown
1. ZAP can run an AJAX spider by using browsers without a GUI. What are these browsers called? - Headless

2. Analysing the Sites tab, what HTTP parameters can be passed to login.php using the POST method? - pass, user

3. What other .php resource, besides nospiders-gallery.php was found by the AJAX spider but not by the regular spider? - /view.php
```

## Scanning for Vulnerabilities

* When running DAST tools, we need to fit our scanning profile to the web application - for example, the given app does not use a database.

* In ZAP, we can modify scanning policies under Analyse -> Scan Policy Manager -> Add.

* For each category, we can modify the two params 'Threshold' and 'Strength'; we can disable the mentioned tests as given.

* We can run a vulnerability scan by going to Tools -> Active Scan and use Starting Point as <http://10.10.35.153:8082> and our customised scanning policy; enable Recurse before starting the scan.

* This will populate the Alerts section, where we will have our findings and descriptions.

```markdown
1. Will disabling some test categories help speed up the scanning phase? - Yea

2. There should be two high-risk alerts in your scan results. One is Path Traversal. What's the name of the other one? - Cross Site Scripting (Reflected)
```

## Authenticated Scans

* For dealing with logins in ZAP, we have to record the authentication process into a ZEST script so that ZAP can replicate the process during scans (disable ZAP HUD from toolbar for this process).

* From the toolbar, select Record A New ZEST Script and choose the type Authentication; add prefix as base URL of our app.

* Once we start recording, every HTTP request going through ZAP proxy will be recorded by the script.

* Click on Open Browser (from toolbar) and navigate to <http://10.10.35.153:8082/login.php> - we will be logging in manually so that ZAP can record the process, using creds "nospiders:nospiders".

* After logging in, we can stop recording by clicking the Record A New ZEST Script button again - we can now check the captured requests.

* We can test the recorded script by pressing Run on Script Console - this shows if we have recorded the process correctly by checking the responses to the requests.

* We have to now create a Context for applying the recorded authentication process - go to Sites, right-click base URL of target app and select Include in Context -> New Context.

* Select Authentication under our web app base URL, and link & load the ZEST script by using Script-based Authentication.

* For authenticated scans, ZAP also needs to define at least one user under Users section - so we can add an user - even though it's the ZEST script doing the work.

* Press OK - now all site resources are marked with a target icon, denoted as part of given Context.

* Now, we can rerun the spider after selecting base URL as starting point, setting up correct Context and user.

* We can check if any new resources were discovered using the spidering session under the Added Nodes tab - we find two new PHP scripts /logout.php and /cowsay.php.

* Now, to prevent ZAP from logging itself out, under Sites, right-click logout.php and exclude from context.

* ZAP also offers ability to specify indicators to identify if the session is active or not; this can be done by the 'Flag as Context' option to denote logged-in or logged-out.

* We can then choose a Verification Strategy for using the configured patterns correctly - here we will be using 'Poll the Specified URL' strategy.

* Running an Active Scan on the app once again by selecting the configured policy, context and user gives us an additional vulnerability.

```markdown
1. Which type of script was used to record the authentication process to our site in ZAP? - ZEST script

2. What additional high-risk vulnerability was found on the site after running the authenticated scan? - remote OS command injection
```

## Checking APIs with ZAP

* ZAP can import APIs defined by OpenAPI (previously known as Swagger), SOAP or GraphQL.

* We have an example at <http://10.10.35.153:8081/swagger.json> - this follows the OpenAPI 2.0 standard.

* API files are sometimes provided with an UI for better understanding - example at <http://10.10.35.153:8081/swagger-ui>

* We can either provide an offline file or a URL to import API definitions into ZAP; for the latter, go to Import > Import an OpenAPI definition from a URL.

* We can then run an Active Scan on the API - under Sites, right-click the URL > Attack > Active Scan.

```markdown
1. What high-risk vulnerability was found on the /asciiart/generate endpoint? - remote OS command injection

2. Based solely on the information presented by the scanner, would you categorise this finding as a false positive? - yea
```

## Integrating DAST into the development pipeline

* To integrate DAST via ZAP in dev pipeline, we can use ```zap2docker```.

* As the environment has everything setup already, we can simply log into Jenkins at <http://10.10.35.153:8080> and explore the available repos under 'thm' organization.

* For the 'main' branch in both repos, we have two stages in the builds - 'Build the Docker image' and 'Deploy the Docker image'.

* We can log into Gitea at <http://10.10.35.153:3000> and open the ```Jenkinsfile``` in both repos to see the commands run at each stage in the builds.

* Both the files contain the required stage for incorporating ```zap2docker``` into our pipeline; we just need to uncomment that stage and commit.

* Once we commit the code, Jenkins notices the change and starts the building process immediately.

* After the scan is finished, we can check the ZAP report by going to the build info on Jenkins, under the Workspaces section.

```markdown
1. Download the ZAP report for the simple-webapp repository. How many medium-risk vulnerabilities were found? - 3

2. Check the main branch of the simple-api repository on Jenkins. One of the builds failed during the Build the Docker image step. What is the number of the pre-existing failed build? - 4

3. Download the ZAP report for the simple-api repository. What high-risk vulnerability was found? - remote OS command injection
```
