<img src="https://cdn.prod.website-files.com/677c400686e724409a5a7409/6790ad949cf622dc8dcd9fe4_nextwork-logo-leather.svg" alt="NextWork" width="300" />

# Build a GraphQL Security Auditor

**Project Link:** [View Project](https://learn.nextwork.org/projects/732d9b9f-08d8-47f3-a8ef-b5736ce05a77)

**Author:** goodluck Oyebisi  
**Email:** goodluckoyebisi5@gmail.com

---

![Image](https://learn.nextwork.org/glowing_blue_adorable_spider/uploads/732d9b9f-08d8-47f3-a8ef-b5736ce05a77_9cylp2v2)

## Building a GraphQL Security Auditor from Scratch

### Project goals and GraphQL's unique attack surface

In this step, I'm setting up dvga so that I can access the graphql home lab for the testing 

### Designing the auditor architecture

In this step, I'm building the python evironment so that I can write the python code for the graphql auditor

## Detecting Schema Exposure with Introspection

### What DVGA's exposed schema reveals

I discovered that DVGA's endpoint at http://localhost:5013/graphql exposes 29 which means the endpoints are attack surface for the testing

## Implementing Denial of Service Vulnerability Checks

### Query depth, alias overloading, and batch query detection

In this step, I'm implementing the code for endponts with ddos so that the auditor can detect ddos vunerablilty

![Image](https://learn.nextwork.org/glowing_blue_adorable_spider/uploads/732d9b9f-08d8-47f3-a8ef-b5736ce05a77_fsftegp3)

### Why unbounded query depth is a DoS risk

Deep nesting is dangerous because it send a lot of request to the server without limit which cause a lot of traffic on the  website and normal users will not have access to the website 


## Catching Information Leakage and CSRF Vulnerabilities

### Field suggestion leakage and GET-based query risks

In this step, I'm setting up csrf query  so that I can  identifies CSRF risk.

![Image](https://learn.nextwork.org/glowing_blue_adorable_spider/uploads/732d9b9f-08d8-47f3-a8ef-b5736ce05a77_zovvnvo9)

### Comparing severity: CSRF vs. schema enumeration

GET-based queries are rated HIGH because  it allows attackers to bypass size limitations, execute state-changing operations via CSRF, and launch volumetric DoS attackswhile field suggestions are LOW because it only reveals the names of available fields when a typo is made

## Running the Full Audit and Generating the Security Report

### Wiring all checks into a color-coded report

In this step, I'm setting up report method so that I can get the report on the scan

### Vulnerabilities discovered in DVGA

The auditor detected five vulnerabilities with severity levels including four high and one medium

## Secret Mission: Circular Fragment DoS Detection

![Image](https://learn.nextwork.org/glowing_blue_adorable_spider/uploads/732d9b9f-08d8-47f3-a8ef-b5736ce05a77_5kavej84)

### CVE-2026-47706 pattern and DVGA's fragment validation

In this project extension, DVGA received a critical severity because the server connection lost after sending circular fragment references

## Reflections and Key Takeaways

### Tools and concepts mastered

The key tools I used include docker,dvga Key concepts I learnt include dos and csrf 

### Time and challenges

This project took me approximately 2 hours The most challenging part was setting up the home lab

I did this project today to learn how to how graphql works Another skill I want to learn is how check for csrf 

---

*Built with [NextWork](https://learn.nextwork.org) - [View this project](https://learn.nextwork.org/projects/732d9b9f-08d8-47f3-a8ef-b5736ce05a77)*
