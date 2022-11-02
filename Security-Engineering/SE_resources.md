# Security Engineering resources

## Contents

### Lecture 1

- [Security by design](#security-by-design)
- [Privacy and data protection by design](#privacy-and-data-protection-by-design)

### Lecture 2

- [Knowledge base on attacks](#knowledge-base-on-attacks)
- [Threat modeling](#threat-modeling)

### Lecture 3

- [Attack trees](#attack-trees)
- [Risk rating and assessment](#risk-rating-and-assessment)

### Lecture 4

- [Secure SDLC](#secure-sdlc)
- [Security requirements](#security-requirements)
- [Abuse cases](#abuse-cases)
- [DevSecOps](#devsecops)
- [Securing web application technologies (SWAT)](#securing-web-application-technologies-swat)

### Lecture 5

- [Code review](#code-review)
- [Heartbleed vulnerability](#heartbleed-vulnerability)
- [iOS SSL flaw](#ios-ssl-flaw)
- [Secrets leakage](#secrets-leakage)

### Lecture 6

- [Container and CI/CD pipeline security](#container-and-cicd-pipeline-security)
- [Top 10 vulnerabilities](#top-10-vulnerabilities)
- [Security of third-party dependencies](#security-of-third-party-dependencies)
- [Security in software supply chain](#security-in-software-supply-chain)

### Lecture 7

- [External security assessments](#external-security-assessments)
- [Bug bounties](#bug-bounties)
- [Deliberately vulnerable web applications](#deliberately-vulnerable-web-applications)
- [Burp suite](#burp-suite)
- [Fuzzing](#fuzzing)
- [SQL injection (SQLi)](#sql-injection-sqli)

### Lecture 8

- [Command injection vulnerabilities](#command-injection-vulnerabilities)
- [Cross-site scripting (XSS)](#cross-site-scripting-xss)

### Lecture 10

- [Testing and security testing](#testing-and-security-testing)
- [Gauntlt](#gauntlt)
- [Formal verification](#formal-verification)

### Lecture 11

- [Ariane V launch accident](#ariane-v-launch-accident)
- [Buffer overflow](#buffer-overflow)
- [CRLF injection attacks](#crlf-injection-attacks)
- [Logs](#logs)
- [Security Culture](#security-culture)
- [Blameless postmortem investigations](#blameless-postmortem-investigations)
- [Security champions](#security-champions)
- [Usable security](#usable-security)

### Remaining lectures

- [Maturity analysis](#maturity-analysis)
- [OSQuery](#osquery)
- [Books available online](#books-available-online)
- [Online trainings](#online-trainings)

## Security by design

- [Security Design Principles - Cryptosmith](https://cryptosmith.com/2013/10/19/security-design-principles/) - Good summary of some of the security design principles, including a reflection of why current textbooks don't refer to them as principles but as security controls.
- [Security by Design Principles according to OWASP](https://patchstack.com/articles/security-design-principles-owasp/) - Security design principles with examples from web applications.
- [The Process of Security - Schneier on Security](https://www.schneier.com/essays/archives/2000/04/the_process_of_secur.html) - In this article, Schneier discusses about how difficult it is to get security right and also mentions the role of considering security design principles to make secure software.
- [Open Source Does not Equal Secure - Schneier on Security](https://www.schneier.com/blog/archives/2020/12/open-source-does-not-equal-secure.html) - Open source means that the code is available for security evaluation, not that it necessarily has been evaluated by anyone.
- [The protection of Information Computer Systems. Saltzer, Schroeder.](https://www.cl.cam.ac.uk/teaching/1011/R01/75-protection.pdf) - Scientific paper (66 pages) first introducing security design principles.

## Privacy and data protection by design

- [Privacy-by-design/default - IT-Branchen](https://itb.dk/persondataforordningen/privacy-by-design-default/) - in Danish. Discusses about the concepts of "privacy by design" and "privacy by default".
- [Privacy by Design: the 7 Foundational Principles](https://www.ipc.on.ca/wp-content/uploads/Resources/7foundationalprinciples.pdf) - This principles are argued to be a bit abstract and difficult to implement in practice.
- [Privacy and data protection by design: from policy to engineering](https://www.enisa.europa.eu/publications/privacy-and-data-protection-by-design/at_download/fullReport) - Report from the European Union Agency for Network and Information Security presenting specific security measures and technologies to provide privacy and data protection.
- [Privacy by design in big data - ENISA](https://www.enisa.europa.eu/publications/big-data-protection) - Focuses on the shift of the discussion from "big data versus privacy" to "big data with privacy".
- [What is differential privacy and how can it protect your data?](https://theconversation.com/explainer-what-is-differential-privacy-and-how-can-it-protect-your-data-90686) - Differential privacy is a method mentioned in the ENISA report to aggregate information and achieve privacy.

## Knowledge base on attacks

- [CAPEC Common Attack Pattern Enumeration and Classification](https://capec.mitre.org/index.html) - By MITRE. Provides a comprehensive dictionary of known patterns of attack employed by adversaries to exploit known weaknesses in cyber-enabled capabilities.
- [CVE Common Vulnerabilities and Exposures](https://cve.mitre.org/index.html) - Catalog of publicly disclosed cybersecurity vulnerabilities.
- [CWE Common Weakness Enumeration](https://cwe.mitre.org/index.html) - Serves as a common language, a measuring stick for security tools, and as a baseline for weakness identification, mitigation, and prevention efforts.
- [MITRE ATT&CK](https://attack.mitre.org/) - Globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
- [MITRE releases D3FEND, defensive measures complimentary to its ATT&CK framework](https://therecord.media/mitre-releases-d3fend-defensive-measures-complimentary-to-its-attck-framework/)
- [An incomplete look at vulnerability databases & scoring methodologies](https://medium.com/@chris.hughes_11070/an-incomplete-look-at-vulnerability-databases-scoring-methodologies-7be7155661e8) - Provides an overview of the differences and similarities between CVE, NVD, CVSSS and other vulnerabilities databases.
- [CISA Releases Best Practices for Mapping to MITRE ATT&CK framework](https://www.cisa.gov/uscert/ncas/current-activity/2021/06/02/cisa-releases-best-practices-mapping-mitre-attckr)
- [Best practices for mapping adversary behavior to the MITRE ATT&CK framework](https://www.cisa.gov/uscert/sites/default/files/publications/Best%20Practices%20for%20MITRE%20ATTCK%20Mapping.pdf)
- [MITRE Engage](https://engage.mitre.org/) - Framework for planning and discussing adversary engagement operations.
- [MITRE updates list of top 25 most dangerous software bugs](https://www.bleepingcomputer.com/news/security/mitre-updates-list-of-top-25-most-dangerous-software-bugs/) - From July 2021.

## Threat modeling

- [Guide to Threat Modeling - by Cyber Security Agency of Singapore (CISA)](https://www.csa.gov.sg/-/media/csa/documents/legislation_supplementary_references/guide-to-cyber-threat-modelling.pdf) - From February 2021. Extensive guide (30 pages) about threat modeling activities, using MITRE ATT&CK and Lockheed Martin Cyber Kill Chain.
- [Pushing left, like a boss - Part 6: Threat Modeling - We Hack Purple](https://wehackpurple.com/pushing-left-like-a-boss-part-6-threat-modelling/) - Well explained introduction to threat modeling within the SDLC.
- [Threat Modeling: 12 available methods](https://insights.sei.cmu.edu/blog/threat-modeling-12-available-methods/) - Briefly explains the different methods to do threat model, including STRIDE, PASTA, and LINDDUN.
- [Threat Model Examples](https://github.com/TalEliyahu/Threat_Model_Examples) - Collection of threat models for various protocols and technologies, including Kubernetes, Docker, and CI/CD pipeline among others.
- [NIST Brings Threat Modeling into the Spotlight](https://thecyberpost.com/news/security/threat-intelligence/nist-brings-threat-modeling-into-the-spotlight/) - Threat modeling is ranked first in NIST’s recent report on recommended technique classes for software verification.
- [#WeHackPurple podcast episode 50 with guest Adam Shostack - Youtube](https://www.youtube.com/watch?v=I9F9nzpjS5U) - (35 min) Podcast interviewing Adam Shostack, author of the book Threat Modeling.
- [Fast, Cheap and Good - by Adam Shostack](https://shostack.org/files/papers/Fast-Cheap-and-Good.pdf) - Adam Shostack's latest whitepaper addressing the argument that claims that threat modeling is a waste of time.
- [Interview: Think like an attacker or accountant?](https://appsecpodcast.securityjourney.com/1730684/8122724-interview-think-like-an-attacker-or-accountant-s01e16-application-security-podcast) - A 28min interview to Adam Shostack, where he argues that "thinking like a hacker" is not the right approach to follow.
- ["Think like an Attacker" is an opt-in mistake - Adam Shostack & friends](https://adam.shostack.org/blog/2016/04/think-like-an-attacker-is-an-opt-in-mistake/) - Blog post explaining what the above podcast is about.
- [OWASP/threat-model-cookbook](https://github.com/OWASP/threat-model-cookbook) - This project is about creating and publishing threat model examples.
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)
- [The Threat Modeling Manifesto - part 1 (podcast)](https://appsecpodcast.securityjourney.com/1730684/8122585-the-threat-modeling-manifesto-part-1) - Approx. 25min podcast. Interesting introduction to what threat modeling is and the ideas behind it.
- [The Threat Modeling Manifesto - part 2 (podcast)](https://appsecpodcast.securityjourney.com/1730684/8122584-the-threat-modeling-manifesto-part-2) - Approx. 24min podcast. Continuation of the podcast above.
- [Application Threat Modeling - by OWASP](https://owasp.org/www-community/Threat_Modeling) - Threat modeling according to OWASP.
- [Threat modeling](https://www.cs.montana.edu/courses/csci476/topics/threat_modeling.pdf) - Slides by Montana State University, with nice examples on library application.
- [Threat Modeling course by British Columbia Provincial Government](https://www.linkedin.com/posts/julienprovenzano_threat-modelling-information-security-branch-activity-6955326649148076032-zY_O?utm_source=share&utm_medium=member_desktop) - From a LinkedIn post.
- [BruCON 0x06 - Keynote - Adam Shostack - Youtube](https://www.youtube.com/watch?v=-2zvfevLnp4) - Youtube video about threat modeling. Approx. 1h.
- [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling) - Curated list of threat modeling resources (books, courses, videos, tools, etc).
- [Why OWASP's Threat Dragon will change the game on threat modeling - TechBeacon](https://techbeacon.com/security/why-owasps-threat-dragon-will-change-game-threat-modeling)
- [GitHub - izar/pytm: A Pythonic framework for threat modeling](https://github.com/izar/pytm)
- [OWASP Threat Dragon](https://www.threatdragon.com) - Website of the open-source threat modeling tool.
- [OWASP Cornupia: gamifying threat modeling](https://owasp.org/www-project-cornucopia/) - OWASP Cornucopia is a card game used to help derive application security requirements during the software development life cycle.
- [Threat modeling basics: Google Play Academy](https://playacademy.exceedlms.com/student/path/63550/activity/220969) - Short course with the basis of threat modeling and STRIDE.

## Attack trees

- [Attack trees by B. Schneier](https://www.schneier.com/academic/archives/1999/12/attack_trees.html) - Post first introducing the concept of attack trees.
- [Draw.io tool for threat modeling and attack trees](https://michenriksen.com/blog/drawio-for-threat-modeling/) - Explains how to use draw.io for threat modeling.
- [Election operations assessment: threat trees and matrices and threat instance risk analyzer](https://www.eac.gov/sites/default/files/eac_assets/1/28/Election_Operations_Assessment_Threat_Trees_and_Matrices_and_Threat_Instance_Risk_Analyzer_(TIRA).pdf) - The largest publicly accessible set of attack trees for e-voting, useful both as an example and to be directly used.
- [Qualys SSL Labs - Projects /SSL Threat Model](https://www.ssllabs.com/projects/ssl-threat-model/) - Another interesting example of attack tree. This one shows the overall attack tree of all threats that could affect SSL, using a mind map representation.

## Risk rating and assessment

- [SP 800-30 Rev. 1, Guide for Conducting Risk Assessments](https://csrc.nist.gov/publications/detail/sp/800-30/rev-1/final)
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- [File:OWASP Risk Rating Template Example.xlsx - OWASP](https://wiki.owasp.org/index.php/File:OWASP_Risk_Rating_Template_Example.xlsx)
- [Security Risk Calculator | Security](https://security.drupal.org/riskcalc)
- [OWASP Risk calculator](https://www.security-net.biz/files/owaspriskcalc.html)
- [GitHub - JavierOlmedo/OWASP-Calculator](https://github.com/JavierOlmedo/OWASP-Calculator) - An online calculator to assess the risk of web vulnerabilities based on OWASP Risk Assessment.

## Secure SDLC

- [Security by design framework. Version 1.0. CSA Singapore.](https://www.csa.gov.sg/~/media/csa/documents/legislation_supplementary_references/security_by_design_framework.pdf) - Framework that proposes building security by design by integrating security into the SDLC.
- [Microsoft Security Development Lifecycle](https://www.microsoft.com/en-us/securityengineering/sdl) -  Introduces security and privacy considerations throughout all phases of the development process.
- [Security development lifecycle : Google Play Academy](https://playacademy.exceedlms.com/student/path/63550/activity/95091) - Short course on secure SDLC.

## Security requirements

- [Security Quality Requirements Engineering (SQUARE) Methodology](https://resources.sei.cmu.edu/asset_files/TechnicalReport/2005_005_001_14594.pdf) - Consists of nine steps that generate a final deliverable of categorized and prioritized security requirements by Carnegie Mellon University.
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) - Provides a basis for testing web application technical security controls and also a list of requirements for secure development.
- [SAFECode Practical Security Stories and Security Tasks for Agile Development Environments](https://safecode.org/publication/SAFECode_Agile_Dev_Security0712.pdf) - Document providing Agile practitioners with a list of security-focused stories and security tasks they can consume "as is" in their Agile-based development environments.

## Abuse cases

- [Abuse Case - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html) - Provides an explanation of what an Abuse Case is, why abuse cases are important when considering the security of an application, and finally provides a proposal for a pragmatic approach to building a list of abuse cases and tracking them for every feature planned for implementation as part of an application.
- [Abuser Stories - Think Like the Bad Guy with Judy Neher - at Agile 2015](https://www.dailymotion.com/video/x36m6lp) - Approx. 8min video first introducing abuse stories or abuse cases.

## DevSecOps

- [SP 800-218, Secure Software Development Framework (SSDF) Version 1.1 | CSRC](https://csrc.nist.gov/publications/detail/sp/800-218/final) - Recommendations for Mitigating the Risk of Software Vulnerabilities by NIST.
- [Nine Key Cloud Security Concentrations & SWAT Checklist | SANS Poster](https://www.sans.org/security-resources/posters/cloud-security-devsecops-practices/200/download) - SANS Poster. See page 2. Last updated in April 2022. This checklist can be used to identify the minimum standard that is required to neutralize vulnerabilities in critical applications.
- [How can we integrate security into the DevOps pipelines?](https://medium.com/swlh/how-to-integrate-security-on-the-devops-pipeline-e36dea836d7b) - Article containing 8 recommendations to start implementing security in the CI/CD pipeline.
- [DevSecOps manifesto](https://www.devsecops.org/)
- [Appsecmap.com](https://appsecmap.com/) - Classifies the commercial and open-source tools required to build out your AppSec program, including SAST, DAST, RASP, WAF, SCA among others.
- [2020 DevSecOps Community Survey by Sonatype](https://www.sonatype.com/hubfs/DevSecOps%20Survey/2020/DSO_Community_Survey_2020_Final_4.1.20.pdf) - Takes a look at the differences between mature and immature DevOps practices in different survey respondents.
- [GitHub - TaptuIT/awesome-devsecops: Curating the best DevSecOps resources and tooling](https://github.com/TaptuIT/awesome-devsecops)
- [Ultimate DevSecOps library](https://github.com/sottlmarek/DevSecOps) - Like an "awesome" repository but without being an official one. Very complete as well.
- [Periodic Table of DevOps Tools](https://digital.ai/devops-tools-periodic-table) - Industry's go-to resource for identifying best-of-breed tools across the software delivery lifecycle.
- [How to deploy a comprehensive DevSecOps solution (Red Hat)](https://www.redhat.com/en/resources/deploy-comprehensive-devsecops-solution-overview) - Framework by Red Hat that provides a solid foundation and blueprint for delivering DevSecOps solutions that deploy and scale more efficiently.
- [DevSecOps Security Controls Infographic](https://accelera.com.au/wp-content/uploads/2020/09/Accelera-DevSecOps-Security-Controls-Infographic_v1.0_2020.pdf)

## Securing web application technologies (SWAT)

- [Securing Web Application Technologies : [SWAT] Checklist | SANS Institute](https://www.sans.org/cloud-security/securing-web-application-technologies/) - Provides a complete list of best practices to secure web applications.

## Code review

- [OWASP Code Review Guide v.2](https://owasp.org/www-project-code-review-guide/) - Book covering the why and how of code reviews, and types of vulnerabilities and how to identify throughout the review.
- [OWASP Benchmark of some static analysis tools](https://owasp.org/www-project-benchmark/) - Java test suite designed to evaluate the accuracy, coverage, and speed of automated software vulnerability detection tools, not only for SAST but also for DAST and IAST tools.
- [OWASP Secure Coding Practices - Quick Reference Guide](https://owasp.org/www-pdf-archive/OWASP_SCP_Quick_Reference_Guide_v2.pdf) - Defines a set of general software security coding practices, in a checklist format, that can be integrated into the software development lifecycle. Implementation of these practices will mitigate most common software vulnerabilities.
- [Don’t Underestimate Grep Based Code Scanning – Little Man In My Head](https://littlemaninmyhead.wordpress.com/2019/08/04/dont-underestimate-grep-based-code-scanning/) - Blog post covering grep-based code scanning, which is an old fashioned way of SAST scanning can still do reasonably well compared to expensive SAST tools in terms of quality of bugs found.
- [List of Source Code Security Analyzers](https://samate.nist.gov/index.php/Source_Code_Security_Analyzers.html) - Long (and still probably non-exhaustive) list of source code scanners, by NIST, with information about licenses and the kind of vulnerabilities they each can find.
- [List of Byte Code Scanners | NISTLock](https://samate.nist.gov/index.php/Byte_Code_Scanners.html)
- [analysis-tools-dev/static-analysis](https://github.com/analysis-tools-dev/static-analysis) - A curated list of static analysis (SAST) tools for all programming languages, config files, build tools, and more. The focus is on tools which improve code quality.
- [Essays: How to Design—And Defend Against—The Perfect Security Backdoor - Schneier on Security](https://www.schneier.com/essays/archives/2013/10/how_to_design_and_de.html) - Sometimes security issues in code do look like deliberate backdoors.
- [bliki: CodeSmell](https://martinfowler.com/bliki/CodeSmell.html) - Martin Fowler's explanation of what code smell is.
- [An Insight into Security Static Analysis Tools - Infosec Resources](https://resources.infosecinstitute.com/topic/insight-security-static-analysis-tools/)
- [Security Code Review 101 — Protecting Data (Part 1) | by Paul Ionescu | Medium](https://medium.com/@paul_io/security-code-review-101-protecting-data-part-1-23e810277f7d) - Interesting article talking about how to spot data breaches during code review.
- [OWASP Secure Coding Practices-Quick Reference Guide](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/migrated_content) - Technology agnostic set of general software security coding practices, in a comprehensive checklist format, that can be integrated into the development lifecycle. The focus is on secure coding requirements, rather then on vulnerabilities and exploits.
- [google/styleguide](https://github.com/google/styleguide) - Style guides and code conventions for Google-originated open-source projects.
- [WebAppSec/Secure Coding Guidelines](https://wiki.mozilla.org/WebAppSec/Secure_Coding_Guidelines) - Establishes a concise and consistent approach to secure application development of Mozilla web applications and web services.

## Heartbleed vulnerability

- [The Role of Static Analysis in Heartbleed | SANS Institute](https://www.sans.org/reading-room/whitepapers/threats/role-static-analysis-heartbleed-35752) - This paper details what the Heartbleed bug is, how the details were disclosed, how vendors responded to it and how static analysis in software quality could have been involved in discovering the bug.
- [Heartbleed, Running the Code - Computerphile](https://www.youtube.com/watch?v=1dOCHwf8zVQ) - Approx. 11min Youtube video that looks and actually also runs the code that exploits the Heartbleed bug.

## iOS SSL flaw

- [Extremely critical crypto flaw in iOS may also affect fully patched Macs | Ars Technica](https://arstechnica.com/information-technology/2014/02/extremely-critical-crypto-flaw-in-ios-may-also-affect-fully-patched-macs/) - Article from 2014, explaining the iOS vulnerability.

## Secrets leakage

- [r2c blog — 🤫 Don't leak your secrets](https://r2c.dev/blog/2021/dont-leak-your-secrets/) -  How to scan your source code for secrets using Semgrep.
- [OWASP's Secrets Management CheatSheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) - This cheat sheet offers best practices and guidelines to help properly implement secrets management.
- [How bad can it Git? Characterizing secret leakage in public GitHub repositories](https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-3_Meli_paper.pdf) - Paper explaining different techniques for detection of secrets, besides the typical grep search.
- [Removing sensitive data from a repository - GitHub Docs](https://docs.github.com/en/github/authenticating-to-github/removing-sensitive-data-from-a-repository#using-filter-branch) - Github's official documentation about how to entirely remove sensitive data you've already committed.
- [BFG Repo-Cleaner by rtyley](https://rtyley.github.io/bfg-repo-cleaner/) - A simpler, faster and open-source alternative to git-filter-branch for deleting big files and removing passwords from Git history.
- [OWASP WrongSecrets | OWASP Foundation](https://owasp.org/www-project-wrongsecrets/) - This is the first Secrets Management-focused vulnerable/p0wnable app.
- [Rewriting your git history, removing files permanently. Cheat sheet included.](https://blog.gitguardian.com/rewriting-git-history-cheatsheet/) - How to successfully and securely eliminate a secret or file from your git history, step by step.

## Container and CI/CD pipeline security

- [Container security best practices: Comprehensive guide](https://sysdig.com/blog/container-security-best-practices/) - Good summary of container security best practices.
- [All about that base image](https://uploads-ssl.webflow.com/6228fdbc6c97145dad2a9c2b/624e2337f70386ed568d7e7e_chainguard-all-about-that-base-image.pdf) - Using “quiet” base images, minimal images with few or no vulnerabilities and built-in security, can reduce security debt, decrease the developer’s workload, and improve development velocity.
- [Building minimal Docker containers for Python applications](https://blog.realkinetic.com/building-minimal-docker-containers-for-python-applications-37d0272c52f3) - On how to keep the image size to a minimum.
- [Best practices when writing a Dockerfile for a Ruby application](https://lipanski.com/posts/dockerfile-ruby-best-practices) - Even though the article focuses on Ruby applications, the best practices mentions are well applicable to all kinds of Dockerfiles, and it's full of examples. It's particularly interesting the part explaining how to avoid leaking secrets inside your docker history.
- [Intro To Docker: Why And How To Use Containers On Any System | Hackaday](https://hackaday.com/2018/09/05/intro-to-docker-why-and-how-to-use-containers-on-any-system/) - Just as quick introduction to Docker.
- [10 real-world stories of how we’ve compromised CI/CD pipelines – NCC Group Research](https://research.nccgroup.com/2022/01/13/10-real-world-stories-of-how-weve-compromised-ci-cd-pipelines/) - Attackers and defenders increasingly understand that build pipelines are highly-privileged targets with a substantial attack surface.
- [Securing DevOps — Review of Approaches | by Arseny Chernov | Medium](https://medium.com/@arsenyspb/securing-devops-review-of-approaches-a801742630ca) - Touches upon Docker and Kubernetes security.

## Top 10 vulnerabilities

- [OWASP Top 10:2021](https://owasp.org/Top10/) - The most well-known ranking of most common vulnerabilities in web applications, from OWASP.
- [OWASP Top Ten project](https://owasp.org/www-project-top-ten/) - The OWASP Top 10 is the reference standard for the most critical web application security risks.
- [Why is Server-Side Request Forgery #10 in OWASP Top 10 2021?](https://www.securityjourney.com/post/why-is-server-side-request-forgery-10-in-owasp-top-10-2021) - Why does the appsec community at large find SSRF such a threat to code security?

## Security of third-party dependencies

- [Pushing Left, Like a Boss — Part 5.2- Use Safe Dependencies – We Hack Purple](https://wehackpurple.com/5-2-safe-dependencies/) - Includes a non-exhaustive list of software that scans 3rd party components for security vulnerabilities, also known as Software Composition Analysis (SCA).
- [OWASP Dependency-Check Project | OWASP](https://owasp.org/www-project-dependency-check/) - Software Composition Analysis (SCA) tool that attempts to detect publicly disclosed vulnerabilities contained within a project's dependencies.
- [Component Analysis | OWASP](https://owasp.org/www-community/Component_Analysis) - Includes a list of SCA tools and a good definition for concepts like provenance and pedigree.
- [Sonatype OSS index](https://ossindex.sonatype.org/) - Free catalogue of open source components and scanning tools to help developers identify vulnerabilities, understand risk, and keep their software safe.
- [The unfortunate reality of insecure libraries](https://cdn2.hubspot.net/hub/203759/file-1100864196-pdf/docs/Contrast_-_Insecure_Libraries_2014.pdf)- Article. In partnership with Sonatype, researchers from Aspect Security analyzed 113 million downloads from the Central Repository of the 31 most popular Java frameworks and security libraries and made some conclusions about this
important aspect of application security.
- [Dependency Hijacking Software Supply Chain Attack Hits More Than 35 Organizations](https://blog.sonatype.com/dependency-hijacking-software-supply-chain-attack-hits-more-than-35-organizations) - Article, february 2021.
- [[Analyst Report] 2021 Open Source Security and Analysis Report](https://www.synopsys.com/software-integrity/resources/analyst-reports/open-source-security-risk-analysis.html) - The 2022 “Open Source Security and Risk Analysis” report examines vulnerabilities and license conflicts found in more than 2400 codebases across 17 industries. The report offers recommendations to help security, legal, risk, and development teams better understand the security and risk landscape accompanying open source development and use.
- [The internet runs on free open-source software. Who pays to fix it? | MIT Technology Review](https://www.technologyreview.com/2021/12/17/1042692/log4j-internet-open-source-hacking/) - Volunteer-run projects like Log4J keep the internet running. The result is unsustainable burnout, and a national security risk when they go wrong.

## Security in software supply chain

- [tag-security/supply-chain-security/supply-chain-security-paper](https://github.com/cncf/tag-security/tree/main/supply-chain-security/supply-chain-security-paper) - CNCF Security Technical Advisory Group effort to ensure the cloud native community has access to information about building, distributing, deploying, and running secure software supply chains.
- [Towards better vendor security assessments - Dropbox](https://dropbox.tech/security/towards-better-vendor-security-assessments) - Results of an experiment Dropbox did to improve vendor security assessments—directly codifying reasonable security requirements into their vendor contracts.
- [What Constitutes a Software Supply Chain Attack?](https://blog.sonatype.com/what-constitutes-a-software-supply-chain-attack?)
- [2021 State of Software Supply Chain - Sonatype report](https://www.sonatype.com/hubfs/Q3%202021-State%20of%20the%20Software%20Supply%20Chain-Report/SSSC-Report-2021_0913_PM_2.pdf)
- [Why You Need a Software Bill of Materials More Than Ever](https://blog.sonatype.com/why-you-need-a-software-bill-of-materials-more-than-ever)
- [What Is the SolarWinds Hack and Why Is It a Big Deal?](https://www.businessinsider.com/solarwinds-hack-explained-government-agencies-cyber-security-2020-12)
- [The US is readying sanctions against Russia over the SolarWinds cyber attack. Here's a simple explanation of how the massive hack happened and why it's such a big deal](https://www.businessinsider.com/solarwinds-hack-explained-government-agencies-cyber-security-2020-12)
- [Codecov Breach: All Questions Answered - SISA AdvisoryCodecov Breach: All Questions Answered](https://www.sisainfosec.com/security-advisory/codecov-breach/)
- [The Full Story of the Stunning RSA Hack Can Finally Be Told | WIRED](https://www.wired.com/story/the-full-story-of-the-stunning-rsa-hack-can-finally-be-told/) - Really good long article about the Chinese hacking of RSA, Inc. They were able to get copies of the seed values to the SecurID authentication token, an anticipation of supply-chain attacks to come.
- [Supply chain insecurity: Keep your eyes on the road with Ruby on Rails](https://www.securityjourney.com/post/supply-chain-insecurity-keep-your-eyes-on-the-road-with-ruby-on-rails)
- [Mitigate against tampering attacks - Secure your software delivery chain](https://www.eficode.com/blog/mitigate-against-attacks-secure-your-software-delivery-chain) - Great explanation of how the source code was compromised in the SolarWinds breach.
- [Want to Write Good Code? Start Using Security Tests - Omer Levi Hevroni](https://www.omerlh.info/2018/10/04/write-good-code-with-security-tests/)
- [anchore/syft](https://github.com/anchore/syft) - CLI tool and library for generating a Software Bill of Materials from container images and filesystems.
- [anchore/grype](https://github.com/anchore/grype) - A vulnerability scanner for container images and filesystems.
- [exploit-CVE-2015-1427](https://github.com/t0kx/exploit-CVE-2015-1427) - Elasticsearch 1.4.0 < 1.4.2 Remote Code Execution exploit and vulnerable container.

## Formal verification

- [What is Formal Verification? - YouTube](https://www.youtube.com/watch?v=-CTNS2D-kbY) - Approx. 2min video.
- [Formal Verification - WireGuard VPN](https://www.wireguard.com/formal-verification/)

## External security assessments

- [Cyber Exercising, Red Teaming and Pentesting | by Jon Lorains | The Startup | Medium](https://medium.com/swlh/cyber-exercising-red-teaming-and-pentesting-5fc11296c4b0)
- [GitHub - veorq/cag: Crypto Audit Guidelines](https://github.com/veorq/cag)

## Bug bounties

- [An Examination of the Bug Bounty Marketplace - Schneier on Security](https://www.schneier.com/blog/archives/2022/01/an-examination-of-the-bug-bounty-marketplace.html) - Covers risks and insecurities for hackers as gig workers, and how bounty programs rely on vulnerable workers to fix their vulnerable systems.
- [A Tour Around the Bug Bounty Zoo | Medium](https://medium.com/swlh/a-tour-around-the-bug-bounty-zoo-c63ccbf4d7cd) - Guide about different bug bounty programs.

## Deliberately vulnerable web applications

- [Awesome-vulnerable](https://github.com/kaiiyer/awesome-vulnerable) - A curated list of vulnerable apps and systems which can be used as penetration testing practice lab.
- [OWASP Vulnerable Web Applications Directory | OWASP Foundation](https://owasp.org/www-project-vulnerable-web-applications-directory) - Comprehensive and maintained registry of known vulnerable web and mobile applications currently available, classified in four categories: Online, Offline, Mobile, and VMs/ISOs.
- [VulnHub](https://www.vulnhub.com/) - Vulnerable virtual machines.

## Burp Suite

- [How to Burp Good – n00py Blog](https://www.n00py.io/2017/10/how-to-burp-good/)

## Fuzzing

- [Fuzz Testing for blackbox security analysis](https://bishopfox.com/blog/fuzzing-aka-fuzz-testing)
- [An Intro to Fuzzing (AKA Fuzz Testing)](https://labs.bishopfox.com/tech-blog/an-intro-to-fuzzing-aka-fuzz-testing)
- [How Heartbleed could've been found](https://blog.hboeck.de/archives/868-How-Heartbleed-couldve-been-found.html)
- [Focus on Fuzzing Archives - SAFECode](https://safecode.org/category/focus-on-fuzzing/) - SAFECode blog series on fuzzing. Very interesting and well explained set of blog posts talking about fuzzing, covering aspects of when we should fuzz, how often, what to fuzz, and a list of relevant fuzzing engines.
- [Fuzzing.org](http://www.fuzzing.org/)
- [Fuzzingbook.org](https://www.fuzzingbook.org)
- [OpenRCE/sulley](https://github.com/OpenRCE/sulley)
- [GitHub - google/oss-fuzz: OSS-Fuzz - continuous fuzzing for open source software](https://github.com/google/oss-fuzz)

## SQL injection (SQLi)

- [Running an SQL Injection Attack - Computerphile](https://www.youtube.com/watch?v=ciNHn38EyRc) - Excellent video explaining SQLi attacks, including blind and union attacks, with a demo.
- [Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html) - From OWASP.
- [SQL Injection Prevention cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [SQL Injection Attacks by Example](http://www.unixwiz.net/techtips/sql-injection.html)
- [SQL Injection Cheat Sheet | Netsparker](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/)
- [W3Schools tutorial on SQL](https://www.w3schools.com/sql/sql_injection.asp) - Always helpful to learn SQL in order to better understand how SQL injections work.
- [SQLi challenges](http://www.zixem.altervista.org/SQLi/) - Fun challenges to practice SQLi, but probably presented in a less pedagogical way than the labs from PortSwigger, where each attack was thoroughly explained.

## Command injection vulnerabilities

- [Command Injections](https://research.cs.wisc.edu/mist/SoftwareSecurityCourse/Chapters/3_8_2-Command-Injections.pdf) - PDF document covering the topic of command injections, with examples.
- [GTFOBins](https://gtfobins.github.io/) - GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.

## Cross-site scripting (XSS)

- [Cross Site Scripting (XSS) Software Attack](https://owasp.org/www-community/attacks/xss/)
- [XSS Filter Evasion](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [Cross Site Scripting Prevention - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Data Validation - OWASP](https://wiki.owasp.org/index.php/Data_Validation)
- [Cross Site Scripting (XSS) Attack Tutorial with Examples, Types & Prevention](https://www.softwaretestinghelp.com/cross-site-scripting-xss-attack-test/)
- [minimaxir/big-list-of-naughty-strings](https://github.com/minimaxir/big-list-of-naughty-strings) - The Big List of Naughty Strings is a list of strings which have a high probability of causing issues when used as user-input data.

## Ariane V launch accident

- [Web section – Software Engineering 10th edition](https://software-engineering-book.com/case-studies/ariane5/)
- [Ariane V: Fligh 501 Failure](https://esamultimedia.esa.int/docs/esa-x-1819eng.pdf) - Official report by the ESA. This report is provided out of curiosity, if you want to know more (and official) details about the accident.
- [Light Years Ahead | The 1969 Apollo Guidance Computer - YouTube](https://www.youtube.com/watch?v=B1J2RMorJXM) - Approx 1h20min Youtube video. Apollo lunar and how it managed errors.

## Buffer overflow

- [Buffer overflow attack](https://web.ecs.syr.edu/~wedu/seed/Book/book_sample_buffer.pdf) - Good document explaining what buffer overflow is and how it can be exploited. Quite technical and with examples in assembly.

- [Buffer Overflow Attack by Computerphile](https://www.youtube.com/watch?v=1S0aBV-Waeo) - Approx. 17min YouTube video.

## CRLF injection attacks

- [What Are CRLF Injection Attacks | Acunetix](https://www.acunetix.com/websitesecurity/crlf-injection/)

## Logs

- [Logging - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [Ingen log - intet indbrud. Betydningen af logs for at kunne undersøge og beskytte sig imod cybertrusler, by CFCS](https://cfcs.dk/globalassets/cfcs/dokumenter/rapporter/-undersogelsesrapport---ingen-log-intet-indbrud-.pdf) - In Danish. Report from June 2021.
- [Pushing Left, Like a Boss — Part 5.9 — Error Handling and Logging – We Hack Purple](https://wehackpurple.com/pushing-left-like-a-boss%E2%80%8A-%E2%80%8Apart-5-9%E2%80%8A-%E2%80%8Aerror-handling-and-logging/)
- [Logning - en del af et godt cyberforsvar, by CFCS](https://cfcs.dk/globalassets/cfcs/dokumenter/vejledninger/cfcs-vejledning-logning.pdf) - In Danish. Report from Nov. 2020.

## Security Culture

- [An Information Security Policy for the Startup | by Ryan McGeehan | Medium](https://medium.com/starting-up-security/starting-up-security-policy-104261d5438a)

## Blameless postmortem investigations

- [What Etsy Does When Things Go Wrong: A 7-Step Guide](https://www.fastcompany.com/3064726/what-etsy-does-when-things-go-wrong-a-7-step-guide)
- [Blameless PostMortems and a Just Culture](https://codeascraft.com/2012/05/22/blameless-postmortems/)
- [Etsy’s Debriefing Facilitation Guide for Blameless Postmortems - Code as Craft](https://codeascraft.com/2016/11/17/debriefing-facilitation-guide/)

## Security champions

- [How to Turn Your Developers into Security Champions](https://www.veracode.com/sites/default/files/pdf/resources/ipapers/how-to-turn-developers-into-security-champions/index.html)
- [Building Security Champions – We Hack Purple](https://wehackpurple.com/building-security-champions)

## Usable security

- [Why Johnny can't encrypt](https://people.eecs.berkeley.edu/~tygar/papers/Why_Johnny_Cant_Encrypt/OReilly.pdf) - Scientific paper.
- [Psychology and Security Resource Page](https://www.cl.cam.ac.uk/~rja14/psysec.html)

## Gauntlt

- [Bringing Security into the Pipeline | Kainos](https://www.kainos.com/bringing-security-pipeline)
- [A closer look at Gauntlt | Kainos](https://www.kainos.com/closer-look-gauntlt) - Explains in more detail what Gauntlt is and does, how to configure it to use security tools other than the ones that come by default (arachni, nmap, curl and a few more). Out of the box Gauntlt only supports XSS attacks with Arachni but this article explains how to expand this functionality. It also demonstrates how to integrate Gauntlt with CI tools like Gitlab-CI.

## Testing and security testing

- [Predicting Software Assurance Using Quality and Reliability Measures](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=435326) - Approx. 20min podcast that discusses how a combination of software development quality and quality techniques can improve software quality. Recommended to listen to, if you have the time.
- [The Agile Testing Pyramid – Agile Coach Journal](https://www.agilecoachjournal.com/2014-01-28/the-agile-testing-pyramid) - Explains the three layers of the testing pyramid (unit, service, and UI) in the context of Agile projects.
- [The Forgotten Layer of the Test Automation Pyramid](https://www.mountaingoatsoftware.com/blog/the-forgotten-layer-of-the-test-automation-pyramid) - Discusses about effective test automation strategies, automating tests at three different levels: UI, service level, and unit tests.
- [Just Say No to More End-to-End Tests](https://testing.googleblog.com/2015/04/just-say-no-to-more-end-to-end-tests.html) - Why the focus shouldn’t be on doing tests from the UI.
- [Goto Fail, Heartbleed, and Unit Testing Culture](https://martinfowler.com/articles/testing-culture.html) - We mentioned in class why these bugs couldn’t be found using fuzz testing. In this article, the software development community suggests that more unit tests could have helped.
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) - Comprehensive guide to test the security of web applications. Good guide to have on your bookmarks for the future. It explains how to set up and conduct a pentest. It provides checklists and techniques of reconnaissance, mapping the environment and the application, and fingerprinting the technology stack. It also offers tests for identity management, authentication functions, session management, authorization, different kinds of injection attacks, and how to find holes in business logic.
- [How to ensure the highest quality of Software code - DEV Community](https://dev.to/someshthakur/how-to-ensures-highest-quality-of-software-4917)

## Maturity analysis

- [OWASP Software Assurance Maturity Model](https://owaspsamm.org/model/)
- [Software Security in Practice - The Building Security In Maturity Model](https://www.yumpu.com/en/document/read/4225338/software-security-in-practice-the-building-security-in-maturity-model) - Good article talking about BSIMM.
- [Online SAMM assessment Calculator](https://concordusa.com/SAMM/)

## OSQuery

- [OSQuery Across the Enterprise](https://medium.com/palantir/osquery-across-the-enterprise-3c3c9d13ec55)
- [How To Monitor Your System Security with osquery on Ubuntu 16.04](https://www.digitalocean.com/community/tutorials/how-to-monitor-your-system-security-with-osquery-on-ubuntu-16-04) - Good resource, full of examples.
- [Exploring Osquery, Fleet, and Elastic Stack as an Open-source solution to Endpoint Detection and Response | SANS Institute](https://www.sans.org/reading-room/whitepapers/detection/exploring-osquery-fleet-elastic-stack-open-source-solution-endpoint-detection-response-39165) - SANS whitepaper.

## Books available online

- [The Security Development Lifecycle](https://bit.ly/35dKSIj) - by Michael Howard and Steve Lipner
- [Secure Programming HOWTO](https://dwheeler.com/secure-programs/Secure-Programs-HOWTO.pdf) - by D. Wheeler.
- [Security Engineering](https://www.cl.cam.ac.uk/~rja14/book.html) - by R. Anderson. Second edition of the book is entirely available for free, as well as some parts of the third edition. It contains also several interesting teaching videos based on the book.

## Online trainings

- [SAFECode Training](https://safecode.org/training/)
