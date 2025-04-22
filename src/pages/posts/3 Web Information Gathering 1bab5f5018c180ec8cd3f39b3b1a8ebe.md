---
title: "Pentest Notes on Web Information Gathering"
date: "2025-04-22"

layout: ../../layouts/PostLayout.astro
description: "Information gathering tools in cybersecurity are vast and varied."

img_path : "/images/webinfogather/theme.jpg"
img_alt: "web image"
---

## Introduction

Web Reconnaissance is the foundation of a thorough security assessment.This process involves systematically and meticulously collecting information about a target website or web application. Think of it as the preparatory phase before delving into deeper analysis and potential exploitation. It forms a critical part of the "Information Gathering" phase of the Penetration Testing Process.

The primary goals of web reconnaissance include:

- **Identifying Assets:** Uncovering all publicly accessible components of the target, such as web pages, subdomains, IP addresses, and technologies used. This step provides a comprehensive overview of the target's online presence.
- **Discovering Hidden Information:** Locating sensitive information that might be inadvertently exposed, including backup files, configuration files, or internal documentation. These findings can reveal valuable insights and potential entry points for attacks.
- **Analysing the Attack Surface:** Examining the target's attack surface to identify potential vulnerabilities and weaknesses. This involves assessing the technologies used, configurations, and possible entry points for exploitation.
- **Gathering Intelligence:** Collecting information that can be leveraged for further exploitation or social engineering attacks. This includes identifying key personnel, email addresses, or patterns of behaviour that could be exploited.

**Types of Reconnaissance**

Web reconnaissance encompasses two fundamental methodologies: active and passive reconnaissance. Each approach offers distinct advantages and challenges, and understanding their
differences is crucial for adequate information gathering.

1. Active Reconnaissance

In active reconnaissance, the attacker directly interacts with the target system to gather information. This interaction can take various forms:

| Technique | Description | Example | Tools | Risk of Detection |
| --- | --- | --- | --- | --- |
| **Port Scanning** | Identifying open ports and services running on the target. | Using Nmap to scan a web server for open ports like 80 (HTTP) and 443 (HTTPS). | Nmap, Masscan, Unicornscan | **High**: Direct interaction may trigger intrusion detection systems and firewalls. |
| **Vulnerability Scanning** | Probing the target for known vulnerabilities. | Running Nessus against a web app to check for SQL injection or XSS vulnerabilities. | Nessus, OpenVAS, Nikto | **High**: Exploit payloads can be detected by security solutions. |
| **Network Mapping** | Mapping the network topology and devices. | Using traceroute to find the path packets take to reach the server. | Traceroute, Nmap | **Medium to High**: Excessive traffic may raise suspicion. |
| **Banner Grabbing** | Retrieving service banners for info like software versions. | Connecting to a server on port 80 to read the HTTP banner. | Netcat, curl | **Low**: Minimal interaction but can still be logged. |
| **OS Fingerprinting** | Identifying the operating system of the target. | Using Nmap `-O` to detect if the target is running Windows, Linux, etc. | Nmap, Xprobe2 | **Low**: Often passive, but advanced techniques can be detected. |
| **Service Enumeration** | Determining versions of services running on open ports. | Using Nmap `-sV` to detect Apache 2.4.50 or Nginx 1.18.0. | Nmap | **Low**: Logged but not usually alert-triggering. |
| **Web Spidering** | Crawling websites to discover hidden pages or files. | Running Burp Suite Spider or ZAP Spider to map website structure. | Burp Suite Spider, OWASP ZAP Spider, Scrapy | **Low to Medium**: Detection possible if not mimicking normal traffic. |
1. Passive Reconnaissance

In contrast, passive reconnaissance involves gathering information about the target without directly interacting with it. This relies on analysing publicly available information and resources, such as:

| Technique | Description | Example | Tools | Risk of Detection |
| --- | --- | --- | --- | --- |
| **Search Engine Queries** | Using search engines to find info on the target (websites, profiles, news, etc.). | Searching Google for "[Target Name] employees" to find employee information or social media profiles. | Google, DuckDuckGo, Bing, Shodan | **Very Low**: Normal internet activity, unlikely to trigger alerts. |
| **WHOIS Lookups** | Retrieving domain registration details via WHOIS databases. | Performing a WHOIS lookup to find the registrant’s name, contact info, and name servers. | `whois` command-line, online WHOIS services | **Very Low**: Legitimate queries, not suspicious. |
| **DNS Analysis** | Analysing DNS records to identify infrastructure like subdomains and mail servers. | Using `dig` to enumerate subdomains of a target domain. | dig, nslookup, host, dnsenum, fierce, dnsrecon | **Very Low**: DNS queries are essential and not typically flagged. |
| **Web Archive Analysis** | Viewing historical website versions to identify changes or hidden data. | Using the Wayback Machine to view past versions of a target website. | Wayback Machine | **Very Low**: Accessing archived sites is normal. |
| **Social Media Analysis** | Gathering target info via social media platforms like LinkedIn, Twitter, or Facebook. | Searching LinkedIn for employees to learn roles and potential social engineering targets. | LinkedIn, Twitter, Facebook, specialised OSINT tools | **Very Low**: Public profile access is not intrusive. |
| **Code Repositories** | Searching public repositories for exposed credentials or vulnerable code. | Looking through GitHub for target-related code with sensitive data. | GitHub, GitLab | **Very Low**: Public code access is expected and not suspicious. |

## WHOIS

WHOIS is a widely used query and response protocol designed to access databases that store information about registered internet resources. Primarily associated with domain names, WHOIS can also provide details about IP address blocks and autonomous systems. Think of it as a giant
phonebook for the internet, letting you look up who owns or is responsible for various online assets.

Each WHOIS record typically contains the following information:

- Domain Name: The domain name itself (e.g.,example.com)
- Registrar: The company where the domain was registered (e.g., GoDaddy, Namecheap)
- Registrant Contact: The person or organization that registered the domain.
- Administrative Contact: The person responsible for managing the domain.
- Technical Contact: The person handling technical issues related to the domain.
- Creation and Expiration Dates: When the domain was registered and when it's set to expire.
- Name Servers: Servers that translate the domain name into an IP address.

## Using WHOIS

Let's consider three scenarios to help illustrate the value of WHOIS data.

**Scenario 1: Phishing Investigation**

An email security gateway flags a suspicious email sent to multiple employees within a company.
The email claims to be from the company's bank and urges recipients to click on a link to update
their account information. A security analyst investigates the email and begins by performing a
WHOIS lookup on the domain linked in the email.

The WHOIS record reveals the following:

- Registration Date: The domain was registered just a few days ago.
- Registrant: The registrant's information is hidden behind a privacy service.
- Name Servers: The name servers are associated with a known bulletproof hosting provider often used for malicious activities.

**Scenario 2: Malware Analysis**

A security researcher is analysing a new strain of malware that has infected several systems within
a network. The malware communicates with a remote server to receive commands and exfiltrate
stolen data. To gain insights into the threat actor's infrastructure, the researcher performs a WHOIS
lookup on the domain associated with the command-and-control (C2) server.

The WHOIS record reveals:

- Registrant: The domain is registered to an individual using a free email service known for anonymity.
- Location: The registrant's address is in a country with a high prevalence of cybercrime.
- Registrar: The domain was registered through a registrar with a history of lax abuse policies.

**Scenario 3: Threat Intelligence Report**

A cybersecurity firm tracks the activities of a sophisticated threat actor group known for targeting
financial institutions. Analysts gather WHOIS data on multiple domains associated with the group's
past campaigns to compile a comprehensive threat intelligence report.

By analysing the WHOIS records, analysts uncover the following patterns:

- Registration Dates: The domains were registered in clusters, often shortly before major attacks.
- Registrants: The registrants use various aliases and fake identities.
- Name Servers: The domains often share the same name servers, suggesting a common
infrastructure.
- Takedown History: Many domains have been taken down after attacks, indicating previous law
enforcement or security interventions.

## DNS

The Domain Name System (DNS) acts as the internet's GPS, guiding your online journey from memorable landmarks (domain names) to precise numerical coordinates (IP addresses). Much like how GPS translates a destination name into latitude and longitude for navigation, DNS translates human-readable domain names (like www.example.com) into the numerical IP addresses (like 192.0.2.1) that computers use to communicate.

**The Hosts File**

The hosts file is a simple text file used to map hostnames to IP addresses, providing a manual method of domain name resolution that bypasses the DNS process. While DNS automates the translation of domain names to IP addresses, the hosts file allows for direct, local overrides. This can be particularly useful for development, troubleshooting, or blocking websites.

 
The hosts file is located in C:\Windows\System32\drivers\etc\hosts on Windows and in /etc/hosts on Linux and MacOS. 

![image](/images/webinfogather/host.png)

Let's explore some of the most common DNS concepts:

| **DNS Concept** | **Description** | **Example** |
| --- | --- | --- |
| Domain Name | A human-readable label for a website or other internet resource. | [www.example.com](http://www.example.com/) |
| IP Address | A unique numerical identifier assigned to each device connected to the internet. | 192.0.2.1 |
| DNS Resolver | A server that translates domain names into IP addresses. | Your ISP's DNS server or 8.8.8.8 (Google DNS) |
| Root Name Server | The top-level servers in the DNS hierarchy. | [a.root-servers.net](http://a.root-servers.net/) (One of 13 root servers) |
| TLD Name Server | Servers responsible for specific top-level domains (e.g., .com, .org). | Verisign for .com, PIR for .org |
| Authoritative Name Server | The server that holds the actual IP address for a domain. | Often managed by hosting providers or domain registrars |
| DNS Record Types | Different types of information stored in DNS. | A, AAAA, CNAME, MX, NS, TXT, etc. |

## Digging DNS

Having established a solid understanding of DNS fundamentals and its various record types, let's now transition to the practical. This section will explore the tools and techniques for leveraging DNS for web reconnaissance. 

**DNS Tools**
DNS reconnaissance involves utilizing specialized tools designed to query DNS servers and extract valuable information.
Here are some of the most popular and versatile tools in the arsenal of web recon professionals:

| Tool | Key Features | Use Cases |
| --- | --- | --- |
| **dig** | Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. | Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records. |
| **nslookup** | Simpler DNS lookup tool, primarily for A, AAAA, and MX records. | Basic DNS queries, quick checks of domain resolution and mail server records. |
| **host** | Streamlined DNS lookup tool with concise output. | Quick checks of A, AAAA, and MX records. |
| **dnsenum** | Automated DNS enumeration tool, supports dictionary attacks, brute-forcing, zone transfers (if allowed). | Discovering subdomains and gathering DNS information efficiently. |
| **fierce** | DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection. | User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets. |
| **dnsrecon** | Combines multiple DNS reconnaissance techniques and supports various output formats. | Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records. |
| **theHarvester** | OSINT tool that gathers info from various sources, including DNS records (e.g., email addresses). | Collecting email addresses, employee information, and domain-related data from multiple sources. |
| **Online DNS Lookup Services** | User-friendly web interfaces for performing DNS lookups. | Quick and easy DNS lookups when CLI tools are unavailable, checking domain availability/info. |

**The Domain Information Groper**

The dig command (Domain Information Groper) is a versatile and powerful utility for querying DNS servers and retrieving various types of DNS records. Its flexibility and detailed and customizable output make it a go-to choice.

| Command | Description |
| --- | --- |
| `dig domain.com` | Performs a default A record lookup for the domain. |
| `dig domain.com A` | Retrieves the IPv4 address (A record) associated with the domain. |
| `dig domain.com AAAA` | Retrieves the IPv6 address (AAAA record) associated with the domain. |
| `dig domain.com MX` | Finds the mail servers (MX records) responsible for the domain. |
| `dig domain.com NS` | Identifies the authoritative name servers for the domain. |
| `dig domain.com TXT` | Retrieves any TXT records associated with the domain. |
| `dig domain.com CNAME` | Retrieves the canonical name (CNAME) record for the domain. |
| `dig domain.com SOA` | Retrieves the start of authority (SOA) record for the domain. |
| `dig @1.1.1.1 domain.com` | Specifies a specific name server to query; in this case 1.1.1.1. |
| `dig +trace domain.com` | Shows the full path of DNS resolution. |
| `dig -x 192.168.1.1` | Performs a reverse lookup on the IP address to find the associated hostname. |
| `dig +short domain.com` | Provides a short, concise answer to the query. |
| `dig +noall +answer domain.com` | Displays only the answer section of the query output. |
| `dig domain.com ANY` | Retrieves all available DNS records (may be blocked by some servers due to RFC 8482). |

**Groping DNS**

![image.png](/images/webinfogather/dig.png)

This output is the result of a DNS query using the dig command for the domain google.com.

## Subdomains

When exploring DNS records, we've primarily focused on the main domain (e.g., example.com) and its associated information. However, beneath the surface of this primary domain lies a potential network of subdomains. These subdomains are extensions of the main domain, often created to organise and separate different sections or functionalities of a website. For instance, a company might use blog.example.com for its blog, shop.example.com for its online store, or mail.example.com for its email services.

**Why is this important for web reconnaissance?**

Subdomains often host valuable information and resources that aren't directly linked from the main
website. This can include:

- **Development and Staging Environments:** Companies often use subdomains to test new features or updates before deploying them to the main site. Due to relaxed security measures, these environments sometimes contain vulnerabilities or expose sensitive information.
- **Hidden Login Portals:** Subdomains might host administrative panels or other login pages that are not meant to be publicly accessible. Attackers seeking unauthorised access can find these as attractive targets.
- **Legacy Applications:** Older, forgotten web applications might reside on subdomains,
potentially containing outdated software with known vulnerabilities.
- **Sensitive Information:** Subdomains can inadvertently expose confidential documents, internal data, or configuration files that could be valuable to attackers.

## Subdomain BruteForcing

Subdomain Brute-Force Enumeration is a powerful active subdomain discovery technique that leverages pre-defined lists of potential subdomain names. This approach systematically tests these names against the target domain to identify valid subdomains. By using carefully crafted wordlists, you can significantly increase the efficiency and effectiveness of your subdomain discovery efforts.

The process breaks down into four steps:

1. Wordlist Selection: The process begins with selecting a wordlist containing potential subdomain names. These wordlists can be:
    - General-Purpose: Containing a broad range of common subdomain names (e.g., dev, staging, blog, mail, admin, test). This approach is useful when you don't know the target's naming conventions.
    - Targeted: Focused on specific industries, technologies, or naming patterns relevant to the target. This approach is more efficient and reduces the chances of false positives.
    - Custom: You can create your own wordlist based on specific keywords, patterns, or intelligence gathered from other sources.

1. Iteration and Querying: A script or tool iterates through the wordlist, appending each word or phrase to the main domain (e.g., example.com) to create potential subdomain names (e.g., dev.example.com, staging.example.com).
2. DNS Lookup: A DNS query is performed for each potential subdomain to check if it resolves to an IP address. This is typically done using the A or AAAA record type.
3. Filtering and Validation: If a subdomain resolves successfully, it's added to a list of valid subdomains. Further validation steps might be taken to confirm the subdomain's existence and functionality (e.g., by attempting to access it through a web browser).

There are several tools available that excel at brute-force enumeration:

| **Tool** | **Description** |
| --- | --- |
| dnsenum | Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains. |
| fierce | User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface. |
| dnsrecon | Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats. |
| amass | Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources. |
| assetfinder | Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans. |
| puredns | Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively. |

## DNS Zone Transfer

While brute-forcing can be a fruitful approach, there's a less invasive and potentially more efficient method for uncovering subdomains – DNS zone transfers. This mechanism, designed for replicating DNS records between name servers, can inadvertently become a goldmine of information for prying eyes if misconfigured.

A DNS zone transfer is essentially a wholesale copy of all DNS records within a zone (a domain and its subdomains) from one name server to another. This process is essential for maintaining consistency and redundancy across DNS servers. However, if not adequately secured, unauthorised parties can download the entire zone file, revealing a complete list of subdomains,
their associated IP addresses, and other sensitive DNS data.

**The Zone Transfer Vulnerability**

While zone transfers are essential for legitimate DNS management, a misconfigured DNS server can transform this process into a significant security vulnerability. The core issue lies in the access controls governing who can initiate a zone transfer. 

In the early days of the internet, allowing any client to request a zone transfer from a DNS server was common practice. This open approach simplified administration but opened a gaping security hole. It meant that anyone, including malicious actors, could ask a DNS server for a complete copy of its zone file, which contains a wealth of sensitive information.

The information gleaned from an unauthorised zone transfer can be invaluable to an attacker. It reveals a comprehensive map of the target's DNS infrastructure, including:

- Subdomains: A complete list of subdomains, many of which might not be linked from the main website or easily discoverable through other means. These hidden subdomains could host development servers, staging environments, administrative panels, or other sensitive resources.
- IP Addresses: The IP addresses associated with each subdomain, providing potential targets for further reconnaissance or attacks.
- Name Server Records: Details about the authoritative name servers for the domain, revealing the hosting provider and potential misconfigurations.

## Virtual Hosts

- DNS directs traffic to the correct server; the web server (Apache, Nginx, IIS) handles requests via Virtual Hosting (VHosts).
- VHosts allow hosting multiple websites on a single server by examining the HTTP Host header.

**Subdomains vs Virtual Hosts**

- **Subdomains**: e.g., `blog.example.com`, have DNS records and may point to the same or different IPs.
- **VHosts**: Server configs that map domains/subdomains to specific `DocumentRoot` paths. Not all need DNS records (can use `/etc/hosts`).

**How VHosts Work**

1. Browser sends HTTP request with domain in Host header.
2. Web server matches it with a VirtualHost config.
3. Corresponding `DocumentRoot` content is served.

| Type | Description |
| --- | --- |
| Name-Based | Most common. Uses Host header. Cost-effective. Issues with SSL/TLS. |
| IP-Based | Each site has a unique IP. Better isolation but less scalable. |
| Port-Based | Sites run on different ports (e.g., 80, 8080). Less user-friendly. |

Several tools are available to aid in the discovery of virtual hosts:

| Tool | Description |
| --- | --- |
| gobuster | Fast vhost discovery via HTTP Host header fuzzing. |
| feroxbuster | Rust-based, fast and recursive discovery tool. |
| ffuf | Web fuzzer with support for vhost fuzzing and response filtering. |

## Certificate Transparency Logs

In the sprawling mass of the internet, trust is a fragile commodity. One of the cornerstones of this trust is the Secure Sockets Layer/Transport Layer Security (SSL/TLS) protocol, which encrypts communication between your browser and a website. At the heart of SSL/TLS lies the digital certificate, a small file that verifies a website's identity and allows for secure, encrypted communication.
However, the process of issuing and managing these certificates isn't foolproof. Attackers can exploit rogue or mis-issued certificates to impersonate legitimate websites, intercept sensitive data, or spread malware. This is where Certificate Transparency (CT) logs come into play.

**What are Certificate Transparency Logs?**

Certificate Transparency (CT) logs are public, append-only ledgers that record the issuance of SSL/TLS certificates. Whenever a Certificate Authority (CA) issues a new certificate, it must submit it to multiple CT logs. Independent organisations maintain these logs and are open for anyone to inspect.

**CT Logs and Web Recon**

Certificate Transparency logs offer a unique advantage in subdomain enumeration compared to other methods. Unlike brute-forcing or wordlist-based approaches, which rely on guessing or predicting subdomain names, CT logs provide a definitive record of certificates issued for a domain and its subdomains. This means you're not limited by the scope of your wordlist or the effectiveness of your brute-forcing algorithm. Instead, you gain access to a historical and comprehensive
view of a domain's subdomains, including those that might not be actively used or easily guessable.

Furthermore, CT logs can unveil subdomains associated with old or expired certificates. These subdomains might host outdated software or configurations, making them potentially vulnerable to exploitation.

In essence, CT logs provide a reliable and efficient way to discover subdomains without the need for exhaustive brute-forcing or relying on the completeness of wordlists. They offer a unique window into a domain's history and can reveal subdomains that might otherwise remain hidden, significantly enhancing your reconnaissance capabilities.

## Fringerprinting

Fingerprinting focuses on extracting technical details about the technologies powering a website or web application. Similar to how a fingerprint uniquely identifies a person, the digital signatures of web servers, operating systems, and software components can reveal critical information about a target's infrastructure and potential security weaknesses. This knowledge empowers attackers to tailor attacks and exploit vulnerabilities specific to the identified technologies.

Fingerprinting serves as a cornerstone of web reconnaissance for several reasons:

- Targeted Attacks: By knowing the specific technologies in use, attackers can focus their efforts on exploits and vulnerabilities that are known to affect those systems. This significantly increases the chances of a successful compromise.
- Identifying Misconfigurations: Fingerprinting can expose misconfigured or outdated software, default settings, or other weaknesses that might not be apparent through other reconnaissance methods.
- Prioritising Targets: When faced with multiple potential targets, fingerprinting helps prioritise efforts by identifying systems more likely to be vulnerable or hold valuable information.
- Building a Comprehensive Profile: Combining fingerprint data with other reconnaissance findings creates a holistic view of the target's infrastructure, aiding in understanding its overall security posture and potential attack vectors.

**Fingerprinting Techniques**

There are several techniques used for web server and technology fingerprinting:

- Banner Grabbing: Banner grabbing involves analysing the banners presented by web servers and other services. These banners often reveal the server software, version numbers, and other details.
- Analysing HTTP Headers: HTTP headers transmitted with every web page request and response contain a wealth of information. The Server header typically discloses the web server software, while the X-Powered-By header might reveal additional technologies like scripting languages or frameworks.
- Probing for Specific Responses: Sending specially crafted requests to the target can elicit unique responses that reveal specific technologies or versions. For example, certain error messages or behaviours are characteristic of particular web servers or software components.
- Analysing Page Content: A web page's content, including its structure, scripts, and other elements, can often provide clues about the underlying technologies. There may be a copyright header that indicates specific software being used, for example.

A variety of tools exist that automate the fingerprinting process, combining various techniques to identify web servers, operating systems, content management systems, and other technologies:

| Tool | Description | Features |
| --- | --- | --- |
| **Wappalyzer** | Browser extension and online service for website technology profiling. | Identifies CMSs, frameworks, analytics tools, and more. |
| **BuiltWith** | Web technology profiler that provides detailed reports on a website's technology stack. | Offers free and paid plans with varying detail levels. |
| **WhatWeb** | Command-line tool for website fingerprinting. | Uses a vast signature database to identify various web technologies. |
| **Nmap** | Versatile network scanner for reconnaissance, service, and OS fingerprinting. | Supports NSE scripts for advanced and specialized scanning. |
| **Netcraft** | Web security service for website fingerprinting and security insights. | Offers detailed reports on tech stack, hosting, and security posture. |
| **wafw00f** | Command-line tool for detecting Web Application Firewalls (WAFs). | Identifies presence, type, and configuration of WAFs. |

## Crawling

Crawling, often called spidering, is the automated process of systematically browsing the World Wide Web. Similar to how a spider navigates its web, a web crawler follows links from one page to another, collecting information. These crawlers are essentially bots that use pre-defined
algorithms to discover and index web pages, making them accessible through search engines or for other purposes like data analysis and web reconnaissance.

**How Web Crawlers Work**

The basic operation of a web crawler is straightforward yet powerful. It starts with a seed URL, which is the initial web page to crawl. The crawler fetches this page, parses its content, and extracts all its links. It then adds these links to a queue and crawls them, repeating the process iteratively. Depending on its scope and configuration, the crawler can explore an entire website or even a vast portion of the web.

**Extracting Valuable Information**

Crawlers can extract a diverse array of data, each serving a specific purpose in the reconnaissance process:

- Links (Internal and External): These are the fundamental building blocks of the web, connecting pages within a website (internal links) and to other websites (external links). Crawlers meticulously collect these links, allowing you to map out a website's structure, discover hidden pages, and identify relationships with external resources.
- Comments: Comments sections on blogs, forums, or other interactive pages can be a goldmine of information. Users often inadvertently reveal sensitive details, internal processes, or hints of vulnerabilities in their comments.
- Metadata: Metadata refers to data about data. In the context of web pages, it includes information like page titles, descriptions, keywords, author names, and dates. This metadata can provide valuable context about a page's content, purpose, and relevance to your
reconnaissance goals.
- Sensitive Files: Web crawlers can be configured to actively search for sensitive files that might be inadvertently exposed on a website. This includes backup files (e.g., .bak, .old), configuration
files (e.g., web.config, settings.php), log files (e.g., error_log, access_log), and other files containing passwords, API keys, or other confidential information. Carefully examining the extracted files, especially backup and configuration files, can reveal a trove of sensitive information, such as database credentials, encryption keys, or even source code snippets.

## Robots.txt

Technically, robots.txt is a simple text file placed in the root directory of a website (e.g., www.example.com/robots.txt). It adheres to the Robots Exclusion Standard, guidelines for how web crawlers should behave when visiting a website. This file contains instructions in the form of
"directives" that tell bots which parts of the website they can and cannot crawl.

**How robots.txt Works**

The directives in robots.txt typically target specific user-agents, which are identifiers for different types of bots.

```
Code: txt
User-agent: *
Disallow: /private/
```

This directive tells all user-agents (* is a wildcard) that they are not allowed to access any URLs that start with /private/. Other directives can allow access to specific directories or files, set crawl delays to avoid overloading a server or provide links to sitemaps for efficient crawling.

**Understanding robots.txt Structure**

The robots.txt file is a plain text document that lives in the root directory of a website. It follows a straightforward structure, with each set of instructions, or "record," separated by a blank line. Each record consists of two main components:

1. User-agent: This line specifies which crawler or bot the following rules apply to. A wildcard (*) indicates that the rules apply to all bots. Specific user agents can also be targeted, such as "Googlebot" (Google's crawler) or "Bingbot" (Microsoft's crawler).
2. Directives: These lines provide specific instructions to the identified user-agent.

Common directives include:

| Directive | Description | Example |
| --- | --- | --- |
| **Disallow** | Specifies paths or patterns that the bot should not crawl. | `Disallow: /admin/` (disallow access to the admin directory) |
| **Allow** | Explicitly permits the bot to crawl specific paths or patterns, even if they fall under a Disallow rule. | `Allow: /public/` (allow access to the public directory) |
| **Crawl-delay** | Sets a delay (in seconds) between successive requests from the bot to avoid overloading the server. | `Crawl-delay: 10` (10-second delay between requests) |
| **Sitemap** | Provides the URL to an XML sitemap for more efficient crawling. | `Sitemap: <https://www.example.com/sitemap.xml`> |

## Well Known URIs

The `.well-known` directory, defined by RFC 8615, is a standardized path (`/.well-known/`) on a web server that hosts important configuration files and metadata related to a website’s services, security, and protocols. This helps browsers, applications, and security tools efficiently discover and access relevant information.

The Internet Assigned Numbers Authority (IANA) maintains a registry of `.well-known` URIs, each with a specific function. Some notable examples include:

- `security.txt`: Provides contact info for reporting security issues (RFC 9116).
- `change-password`: Directs users to a password change page.
- `openid-configuration`: Lists OpenID Connect settings and endpoints.
- `assetlinks.json`: Verifies digital asset ownership (e.g., mobile apps).
- `mta-sts.txt`: Defines SMTP MTA Strict Transport Security policy (RFC 8461).

### Application in Web Recon:

During reconnaissance, `.well-known` endpoints can reveal useful configuration details. For instance, the `openid-configuration` URI provides JSON metadata containing:

- **Endpoints** (authorization, token, userinfo)
- **JWKS URI** (for cryptographic keys)
- **Supported scopes & response types**
- **Signing algorithms**

This structured and public information helps security professionals explore authentication mechanisms, discover endpoints, and map out a website’s security posture more effectively.

## Creepy Crawlies

Web crawling is a powerful technique in reconnaissance, but it doesn't have to be overwhelming. A variety of tools can automate the process, making it faster and more efficient. Below are some of the most popular web crawlers used in cybersecurity and data extraction:

### Popular Web Crawlers

- **Burp Suite Spider**
    
    A component of Burp Suite used to map web applications, find hidden content, and discover vulnerabilities.
    
- **OWASP ZAP (Zed Attack Proxy)**
    
    Free and open-source scanner with an integrated spider to identify vulnerabilities.
    
- **Scrapy (Python Framework)**
    
    Highly flexible and scalable framework to build custom web crawlers. Ideal for complex data extraction.
    
- **Apache Nutch**
    
    Java-based crawler suitable for large-scale web crawling. Highly extensible but requires technical expertise.
    

> Always follow ethical practices!
> 
> 
> Get permission before crawling, avoid heavy request loads, and respect server resources.
> 

---

### Using Scrapy for Reconnaissance

We'll use **Scrapy** and a custom spider called **ReconSpider** to crawl `inlanefreight.com`.

**Installing Scrapy**

```bash
pip3 install scrapy
```

**Running ReconSpider**

```
python3 ReconSpider.py http://inlanefreight.com
```

```json
{
"emails": [
"lily.floid@inlanefreight.com",
"cvs@inlanefreight.com",
...
],
"links": [
"https://www.themeansar.com",
"https://www.inlanefreight.com/index.php/offices/",
...
],
"external_files": [
"https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf",
...
],
"js_files": [
"https://www.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.
...
],
"form_fields": [],
"images": [
"https://www.inlanefreight.com/wp-content/uploads/2021/03/AboutUs_01-1024x810.png",
...
],
"videos": [],
"audio": [],
"comments": [
"<!-- #masthead -->",
...
]
}
```

Each key in the JSON file represents a different type of data extracted from the target website:

| **JSON Key** | **Description** |
| --- | --- |
| `emails` | Lists email addresses found on the domain. |
| `links` | Lists URLs of links found within the domain. |
| `external_files` | Lists URLs of external files such as PDFs. |
| `js_files` | Lists URLs of JavaScript files used by the website. |
| `form_fields` | Lists form fields found on the domain (empty in this example). |
| `images` | Lists URLs of images found on the domain. |
| `videos` | Lists URLs of videos found on the domain (empty in this example). |
| `audio` | Lists URLs of audio files found on the domain (empty in this example). |
| `comments` | Lists HTML comments found in the source code. |

## Search Engine Discovery

Search engine discovery, a form of OSINT (Open Source Intelligence), uses search engines to uncover valuable information about websites, organizations, and individuals. By applying specialized search operators and techniques, security professionals can extract hidden data such as login pages, sensitive documents, employee info, and exposed credentials—making search engines powerful tools for web reconnaissance beyond their everyday use.

**Why Search Engine Discovery Matters**

Search engine discovery is a crucial component of web reconnaissance for several reasons:

- Open Source: The information gathered is publicly accessible, making it a legal and ethical way to gain insights into a target.
- Breadth of Information: Search engines index a vast portion of the web, offering a wide range of potential information sources.
- Ease of Use: Search engines are user-friendly and require no specialised technical skills.
- Cost-Effective: It's a free and readily available resource for information gathering.

The information you can pull together from Search Engines can be applied in several different ways as well:

- Security Assessment: Identifying vulnerabilities, exposed data, and potential attack vectors.
- Competitive Intelligence: Gathering information about competitors' products, services, and strategies.
- Investigative Journalism: Uncovering hidden connections, financial transactions, and unethical practices.
- Threat Intelligence: Identifying emerging threats, tracking malicious actors, and predicting potential attacks.

However, it's important to note that search engine discovery has limitations. Search engines do not index all information, and some data may be deliberately hidden or protected.

### Search Operators

Let's delve into some essential and advanced search operators:

| Operator | Description | Example | Example Description |
| --- | --- | --- | --- |
| `site:` | Limits results to a specific website or domain | `site:example.com` | Find all publicly accessible pages on [example.com](http://example.com/) |
| `inurl:` | Finds pages with a specific term in the URL | `inurl:login` | Search for login pages on any website |
| `filetype:` | Searches for files of a particular type | `filetype:pdf` | Find downloadable PDF documents |
| `intitle:` | Finds pages with a specific term in the title | `intitle:"confidential report"` | Look for documents titled "confidential report" |
| `intext:`/`inbody:` | Searches for a term within the body text of pages | `intext:"password reset"` | Identify webpages containing the term “password reset” |
| `cache:` | Displays the cached version of a webpage (if available) | `cache:example.com` | View the cached version of [example.com](http://example.com/) |
| `link:` | Finds pages that link to a specific webpage | `link:example.com` | Identify websites linking to [example.com](http://example.com/) |
| `related:` | Finds websites related to a specific webpage | `related:example.com` | Discover websites similar to [example.com](http://example.com/) |
| `info:` | Provides a summary of information about a webpage | `info:example.com` | Get basic details about [example.com](http://example.com/) |
| `define:` | Provides definitions of a word or phrase | `define:phishing` | Get a definition of "phishing" from various sources |
| `numrange:` | Searches for numbers within a specific range | `site:example.com numrange:1000-2000` | Find pages on [example.com](http://example.com/) with numbers between 1000 and 2000 |
| `allintext:` | Finds pages containing all specified words in body text | `allintext:admin password reset` | Search for pages containing both "admin" and "password reset" |
| `allinurl:` | Finds pages containing all specified words in the URL | `allinurl:admin panel` | Look for pages with "admin" and "panel" in the URL |
| `allintitle:` | Finds pages containing all specified words in the title | `allintitle:confidential report 2023` | Search for pages with "confidential", "report", and "2023" in the title |
| `AND` | Narrows results requiring all terms to be present | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages specifically on [example.com](http://example.com/) |
| `OR` | Broadens results including pages with any terms | `"linux" OR "ubuntu" OR "debian"` | Search for webpages mentioning Linux, Ubuntu, or Debian |
| `NOT` | Excludes results containing the specified term | `site:bank.com NOT inurl:login` | Find pages on [bank.com](http://bank.com/) excluding login pages |
| `*` (wildcard) | Represents any character or word | `site:socialnetwork.com filetype:pdf user* manual` | Search for user manuals in PDF format on [socialnetwork.com](http://socialnetwork.com/) |
| `..` (range) | Finds results within a numerical range | `site:ecommerce.com "price" 100..500` | Look for products priced between 100 and 500 on an e-commerce website |
| `""` (quotes) | Searches for exact phrases | `"information security policy"` | Find documents mentioning the exact phrase "information security policy" |
| `-` (minus) | Excludes terms from the search results | `site:news.com -inurl:sports` | Search for news articles on [news.com](http://news.com/) excluding sports-related content |

**Google Dorking**

Google Dorking, also known as Google Hacking, is a technique that leverages the power of search operators to uncover sensitive information, security vulnerabilities, or hidden content on websites,
using Google Search.
Here are some common examples of Google Dorks:

**Finding Login Pages:**

- site:example.com inurl:login
- site:example.com (inurl:login OR inurl:admin)

Identifying Exposed Files:

- site:example.com filetype:pdf
- site:example.com (filetype:xls OR filetype:docx)

Uncovering Configuration Files:

- site:example.com inurl:config.php
- site:example.com (ext:conf OR ext:cnf) (searches for extensions commonly used for configuration files)

Locating Database Backups:

- site:example.com inurl:backup
- site:example.com filetype:sql

## Web Archives

In the fast-paced digital world, websites come and go, leaving only fleeting traces of their existence behind. However, thanks to the Internet Archive's Wayback Machine, we have a unique opportunity to revisit the past and explore the digital footprints of websites as they once were.

### What is the Wayback Machine?

The Wayback Machine is a digital archive of the World Wide Web and other information on the Internet. Founded by the Internet Archive, a non-profit organization, it has been archiving websites since 1996.

It allows users to "go back in time" and view snapshots of websites as they appeared at various points in their history. These snapshots, known as captures or archives, provide a glimpse into the past versions of a website, including its design, content, and functionality.

### How Does the Wayback Machine Work?

The Wayback Machine operates by using web crawlers to capture snapshots of websites at regular intervals automatically. These crawlers navigate through the web, following links and indexing pages, much like how search engine crawlers work. However, instead of simply indexing the information for search purposes, the Wayback Machine stores the entire content of the pages, including HTML, CSS, JavaScript, images, and other resources.

## Automating Recon

While manual reconnaissance can be effective, it can also be time-consuming and prone to human error. Automating web reconnaissance tasks can significantly enhance efficiency and accuracy, allowing you to gather information at scale and identify potential vulnerabilities more rapidly.

### Why Automate Reconnaissance?

Automation offers several key advantages for web reconnaissance:

- **Efficiency:** Automated tools can perform repetitive tasks much faster than humans, freeing up valuable time for analysis and decision-making.
- **Scalability:** Automation allows you to scale your reconnaissance efforts across a large number of targets or domains, uncovering a broader scope of information.
- **Consistency:** Automated tools follow predefined rules and procedures, ensuring consistent and reproducible results and minimising the risk of human error.
- **Comprehensive Coverage:** Automation can be programmed to perform a wide range of reconnaissance tasks, including DNS enumeration, subdomain discovery, web crawling, port scanning, and more, ensuring thorough coverage of potential attack vectors.
- **Integration:** Many automation frameworks allow for easy integration with other tools and platforms, creating a seamless workflow from reconnaissance to vulnerability assessment and exploitation.

### FinalRecon

FinalRecon offers a wealth of recon information:

- **Header Information:** Reveals server details, technologies used, and potential security misconfigurations.
- **Whois Lookup:** Uncovers domain registration details, including registrant information and contact details.
- **SSL Certificate Information:** Examines the SSL/TLS certificate for validity, issuer, and other relevant details.
- **Crawler:**
    - HTML, CSS, JavaScript: Extracts links, resources, and potential vulnerabilities from these files.
    - Internal/External Links: Maps out the website's structure and identifies connections to other domains.
    - Images, robots.txt, sitemap.xml: Gathers information about allowed/disallowed crawling paths and website structure.
    - Links in JavaScript, Wayback Machine: Uncovers hidden links and historical website data.
- **DNS Enumeration:** Queries over 40 DNS record types, including DMARC records for email security assessment.
- **Subdomain Enumeration:** Leverages multiple data sources ([crt.sh](http://crt.sh/), AnubisDB, ThreatMiner, CertSpotter, Facebook API, VirusTotal API, Shodan
API, BeVigil API) to discover subdomains.
- **Directory Enumeration:** Supports custom wordlists and file extensions to uncover hidden directories and files.
- **Wayback Machine:** Retrieves URLs from the last five years to analyse website changes and potential vulnerabilities.