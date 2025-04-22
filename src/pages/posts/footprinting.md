---
title: "Pentest Notes on Footprinting"
date: "2025-04-22"

layout: ../../layouts/PostLayout.astro
description: "Footprinting is an ethical hacking technique used to gather as much data as possible about a specific targeted computer system"

img_path : "/images/footprinting/theme.jpeg"
img_alt: "web image"
---

## Enumeration Principles

Enumeration is a widely used term in cybersecurity. It stands for information gathering using active (scans) and passive (use of third-party providers) methods. 

It is important to note that OSINT is an independent procedure and should be performed separately from enumeration because OSINT is based exclusively on passive information gathering and does not involve active enumeration of the given target. 

Enumeration is a loop in which we repeatedly gather information based on what data we have or have already discovered.

Information can be gathered from domains, IP addresses, accessible services, and many other sources.

The enumeration goal is not to get at the systems but to find all the ways to get there.

Critical questions to ask ourselves are:

- What can we see?
- What reasons can we have for seeing it?
- What image does what we see create for us?
- What do we gain from it?
- How can we use it?
- What can we not see?
- What reasons can there be that we do not see?
- What image results from what we do not see?

| No. | Principle |
| --- | --- |
| 1 | There is more than meets the eye. Consider all points of view. |
| 2 | Distinguish between what we see and what we do not see. |
| 3 | There are always ways to gain more information. Understand the target. |

## Enumeration Methodology

The whole enumeration process is divided into three different levels:

1. Infrastructure-based enumeration, 
2. Host-based enumeration, 
3. OS-based enumeration.

This methodology is nested in 6 layers;

| Layer | Description | Information Categories |
| --- | --- | --- |
| **1. Internet Presence** | Identification of internet presence and externally accessible infrastructure. | Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures |
| **2. Gateway** | Identify the possible security measures to protect the company's external and internal infrastructure. | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare |
| **3. Accessible Services** | Identify accessible interfaces and services that are hosted externally or internally. | Service Type, Functionality, Configuration, Port, Version, Interface |
| **4. Processes** | Identify the internal processes, sources, and destinations associated with the services. | PID, Processed Data, Tasks, Source, Destination |
| **5. Privileges** | Identification of the internal permissions and privileges to the accessible services. | Groups, Users, Permissions, Restrictions, Environment |
| **6. OS Setup** | Identification of the internal components and systems setup. | OS Type, Patch Level, Network Config, OS Environment, Configuration |

Layer No.1: Internet Presence

The goal of this layer is to identify all possible target systems and interfaces that can be tested.

Layer No.2: Gateway

The goal is to understand what we are dealing with and what we have to watch out for.

Layer No.3: Accessible Services

This layer aims to understand the reason and functionality of the target system and gain the necessary knowledge to communicate with it and exploit it for our purposes effectively.

Layer No.4: Processes

The goal here is to understand these factors and identify the dependencies between them.

Layer No.5: Privileges

It is crucial to identify these and understand what is and is not possible with these privileges.

Layer No.6: OD Setup

The goal here is to see how the administrators manage the systems and what sensitive internal information we can glean from them.

## Domain Information

Domain information is a core component of any penetration test, and it is not just about the  subdomains but about the entire presence on the Internet. Therefore, we gather information and try to understand the company's functionality.

This type of information is gathered passively without direct and active scans. In other words, we remain hidden and navigate as "customers" or "visitors" to avoid direct connections to the company that could expose us. However, when passively gathering information, we can use third-party services to understand the company better.

- SSL certs & crt.sh help identify **active subdomains**.
- IPs linked to company-owned infrastructure are **targets for further testing**.
- Shodan reveals open ports, services, SSL info for discovered IPs.
- DNS records give **extra insights** into company email, hosting, and verification setups.

## Cloud Resources

The use of cloud, such as AWS, GCP, Azure, and others, is now one of the essential components for many companies nowadays. After all, all companies want to be able to do their work from anywhere, so they need a central point for all management. This is why services from Amazon (AWS), Google (GCP), and Microsoft (Azure) are ideal for this purpose.

Even though cloud providers secure their infrastructure centrally, this does not mean that companies are free from vulnerabilities. The configurations made by the administrators may nevertheless make the company's cloud resources vulnerable. This often starts with the S3
buckets (AWS), blobs (Azure), cloud storage (GCP), which can be accessed without authentication if configured incorrectly.

Often cloud storage is added to the DNS list when used for administrative purposes by other employees. This step makes it much easier for the employees to reach and manage them. Let us stay with the case that a company has contracted us, and during the IP lookup, we have
already seen that one IP address belongs to the [s3-website-us-west-2.amazonaws.com](http://s3-website-us-west-2.amazonaws.com/) server.

However, there are many different ways to find such cloud storage. One of the easiest and most used is Google search combined with Google Dorks. For example, we can use the Google Dorks inurl: and intext: to narrow our search to specific terms. In the following example,
we see red censored areas containing the company name.

## Staff

Searching for and identifying employees on social media platforms can also reveal a lot about the teams' infrastructure and makeup. This, in turn, can lead to us identifying which technologies, programming languages, and even software applications are being used. To a large extent, we will also be able to assess each person's focus based on their skills. The posts and material shared with others are also a great indicator of what the person is currently engaged in and what that person currently feels is important to share with others.

Employees can be identified on various business networks such as LinkedIn or Xing. Job postings from companies can also tell us a lot about their infrastructure and give us clues about what we should be looking for.

Suppose we are trying to find the infrastructure and technology the company is most likely to use. We should look for technical employees who work both in development and security. Because based on the security area and the employees who work in that area, we will also be
able to determine what security measures the company has put in place to secure itself.

## FTP

The File Transfer Protocol (FTP) is one of the oldest protocols on the Internet. The FTP runs within the application layer of the TCP/IP protocol stack. Thus, it is on the same layer as HTTP or POP.

- FTP (File Transfer Protocol) is used to upload/download files.
- Uses two TCP channels:
    1. Control Channel (Port 21)
        - Client ↔ Server communication.
        - Sends commands, receives status codes.
    2. Data Channel (Port 20)
        - Transfers files (upload/download).
        - Used only for data.
- Error Handling:
    - FTP can resume transfers if the connection breaks and is re-established.

- Active FTP:
    - Client connects to server via port 21 (control).
    - Server connects back to client on a client-specified port (data).
    - Issue: Firewalls on the client side may block the server's incoming connection.
- Passive FTP:
    - Client connects to server via port 21 (control).
    - The server sends a port number for data transfer.
    - Client initiates both connections (control & data).
    - Works better behind firewalls.

Usually, we need credentials to use FTP on a server. However, there is also the possibility that a server offers anonymous FTP. The server operator then allows any user to upload or download files via FTP without using a password.

### TFTP

Trivial File Transfer Protocol (TFTP) is simpler than FTP and performs file transfers between client and server processes. However, it does not provide user authentication and other valuable features supported by FTP. In addition, while FTP uses TCP, TFTP uses UDP, making it an unreliable
protocol and causing it to use UDP-assisted application layer recovery.

Commands of TFTP:

| Command | Description |
| --- | --- |
| connect | Sets the remote host, and optionally the port, for file transfers. |
| get | Transfers a file or set of files from the remote host to the local host. |
| put | Transfers a file or set of files from the local host onto the remote host. |
| quit | Exits tftp. |
| status | Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on. |
| verbose | Turns verbose mode, which displays additional information during file transfer, on or off. |

One of the most used FTP servers on Linux-based distributions is vsFTPd. The default configuration of vsFTPd can be found in /etc/vsftpd.conf, and some settings are already predefined by default.

There are many different security-related settings we can make on each FTP server. These can have various purposes, such as testing connections through the firewalls, testing routes, and authentication mechanisms. One of these authentication mechanisms is the anonymous user. This is often used to allow everyone on the internal network to share files and data without accessing each other's computers.

With the standard FTP client (ftp), users can connect to an FTP server and log in using an anonymous account, especially in internal environments where all users are known. This setup is often used to temporarily speed up file exchanges. When connecting to a vsFTPd server, a 220 response code and a banner (with service details) are displayed. Many FTP servers allow anonymous access, enabling users to list or access certain files without credentials—useful for gathering information even if downloads aren't allowed.

In ftp, we can download a file with `get` command and upload a file with `put` command.

## SMB

Server Message Block (SMB) is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network.

The SMB protocol enables the client to communicate with other participants in the same network to access files or services shared with it on the network.

In IP networks, SMB uses TCP protocol for this purpose, which provides for a three-way handshake between client and server before a connection is finally established.

### Samba

There is an alternative implementation of the SMB server called Samba, which is developed for Unix-based operating systems. Samba implements the Common Internet File System (CIFS) network protocol. CIFS is a dialect of SMB, meaning it is a specific implementation of the SMB protocol originally created by Microsoft. This allows Samba to communicate effectively with newer Windows systems. Therefore, it is often referred to as SMB/CIFS.

| SMB Version | Supported | Features |
| --- | --- | --- |
| CIFS | Windows NT 4.0 | Communication via NetBIOS interface |
| SMB 1.0 | Windows 2000 | Direct connection via TCP |
| SMB 2.0 | Windows Vista, Windows Server 2008 | Performance upgrades, improved message signing, caching feature |
| SMB 2.1 | Windows 7, Windows Server 2008 R2 | Locking mechanisms |
| SMB 3.0 | Windows 8, Windows Server 2012 | Multichannel connections, end-to-end encryption, remote storage access |
| SMB 3.0.2 | Windows 8.1, Windows Server 2012 R2 |  |
| SMB 3.1.1 | Windows 10, Windows Server 2016 | Integrity checking, AES-128 encryption |

In a network, each host participates in the same workgroup. A workgroup is a group name that identifies an arbitrary collection of computers and their resources on an SMB network. There can be multiple workgroups on the network at any given time.

Now we can display a list (-L) of the server's shares with the smbclient command from our host. We use the so-called null session (-N), which is anonymous access without the input of existing users or valid passwords.

We can download a file and folder using get command.

## NFS

Network File System (NFS) is a network file system developed by Sun Microsystems and has the same purpose as SMB. Its purpose is to access file systems over a network as if they were local. 

However, it uses an entirely different protocol. NFS is used between Linux and Unix systems.
This means that NFS clients cannot communicate directly with SMB servers. NFS is an Internet standard that governs the procedures in a distributed file system. 

While NFS protocol version 3.0 (NFSv3), which has been in use for many years, authenticates the client computer, this changes with NFSv4. 

| Version | Features |
| --- | --- |
| NFSv2 | It is older but is supported by many systems and was initially operated entirely over UDP. |
| NFSv3 | It has more features, including variable file size and better error reporting, but is not fully compatible with NFSv2 clients. |
| NFSv4 | Includes Kerberos, works through firewalls and on the Internet, no longer requires portmappers, supports ACLs, applies state-based operations, and provides performance improvements and high security. It is also the first version to have a stateful protocol. |

### NFS Version 4.1 (RFC 8881)

Cluster Support & Parallel Access

- Supports cluster server deployments
- Introduces parallel access to files via pNFS (parallel NFS) extension
- Adds session trunking ( NFS multipathing) for enhanced performance

Port Simplification

- Uses only one port (2049) over UDP/TCP, simplifying firewall configurations
- *Note:* Older versions used multiple ports

Underlying Protocols

- Based on ONC-RPC / SUN-RPC
- Exposed on TCP/UDP port 111
- Uses XDR (External Data Representation) for platform-independent data exchange

Authentication & Authorization

- NFS protocol itself lacks built-in authentication mechanisms
- Authentication is handled by the RPC layer
- Authorization is derived from the file system (e.g., UNIX permissions)
- Server translates client info (UID/GID) to its own file system format

Limitations & Security Concerns

- Relies heavily on UNIX UID/GID and group memberships
- No guarantee that client and server UID/GID mappings match
- Server performs no further verification
- Recommended only for use in trusted environments when using this model

## DNS

Domain Name System (DNS) is an integral part of the Internet. For example, through domain names, such as [academy.hackthebox.com](http://academy.hackthebox.com/) or [www.hackthebox.com](http://www.hackthebox.com/), we can reach the web servers that the hosting provider has assigned one or more specific IP addresses. DNS is a system for resolving computer names into IP addresses, and it does not have a central database.

There are several types of DNS servers that are used worldwide:

| Server Type | Description |
| --- | --- |
| DNS Root Server | The root servers of the DNS are responsible for the top-level domains (TLD). They are only requested if the name server does not respond. There are 13 root servers globally, coordinated by ICANN. |
| Authoritative Nameserver | Authoritative name servers hold authority for a particular zone and provide binding answers to queries within their area of responsibility. If unable to answer, the root server takes over. |
| Non-authoritative Nameserver | Non-authoritative name servers collect information on DNS zones through recursive or iterative querying but are not responsible for a specific zone. |
| Caching DNS Server | Caching DNS servers store information from other name servers for a specified time. The duration is determined by the authoritative name server. |
| Forwarding Server | Forwarding servers forward DNS queries to another DNS server for resolution. |
| Resolver | Resolvers perform name resolution locally on the computer or router but are not authoritative DNS servers. |

DNS is mainly unencrypted. Devices on the local WLAN and Internet providers can therefore hack in and spy on DNS queries. Since this poses a privacy risk, there are now some solutions for DNS encryption. By default, IT security professionals apply DNS over TLS (DoT) or DNS over HTTPS (DoH) here. In addition, the network protocol DNSCrypt also encrypts the traffic between the computer and the name server.

However, the DNS does not only link computer names and IP addresses. It also stores and outputs additional information about the services associated with a domain. A DNS query can therefore also be used, for example, to determine which computer serves as the e-mail server for the domain in question or what the domain's name servers are called.

The SOA record is located in a domain's zone file and specifies who is responsible for the operation of the domain and how DNS information for the domain is managed.

![soa](/images/footprinting/soa.png)

The dot (.) is replaced by an at sign (@) in the email address. In this example, the email address of the administrator is awsdns-hostmaster@amazon.com.

There are many different configuration types for DNS. Therefore, we will only discuss the most important ones to illustrate better the functional principle from an administrative point of view. All DNS servers work with three different types of configuration files:

1. local DNS configuration files
2. zone files
3. reverse name resolution files

**Zone Transfer in DNS**

Zone transfer is the process of copying DNS zone data from one server to another, usually over TCP port 53. The process is called Asynchronous Full Transfer Zone (AXFR).

- **Purpose**:
    - Ensures all DNS servers (primary and secondary) have identical zone files.
    - Increases reliability, helps in load distribution, and protects the primary serve**r** from attacks.

The **primary server** (master) holds the original zone data. **Secondary servers** (slaves) obtain data from the master. A secondary can act as both a **slave** (to receive data) and a **master** (to serve data to other slaves).

The slave checks the **SOA (Start of Authority)** record from the master at regular intervals (usually **1 hour**). If the master’s **serial number** is higher, it means updates are available, triggering a zone transfer.

## SMTP

- SMTP(Simple Mail Transfer Protocol) is a protocol used for sending emails over an IP network.
- It works:
    - Between an email client and an outgoing mail server
    - Between two SMTP servers
- Default port: TCP port 25
- Port 587: Used for receiving mail from authenticated users/servers, often with STARTTLS for encryption
- Port 465: Sometimes used for SSL/TLS encrypted connections
- SMTP is a client-server-based protocol but can also work between two SMTP servers.
- Initially, the client authenticates with a username and password.
- Then, the client sends:
    - Sender and recipient addresses
    - Email content
    - Other parameters
- After transmission, the connection is terminated.
- The email is passed from one SMTP server to another until it reaches the recipient's server.
- By default, SMTP is unencrypted and sends data in plaintext.
- STARTTLS: Upgrades a plaintext connection to an encrypted one.
- Uses SSL/TLS to encrypt commands, data, and authentication info.
- Uses ESMTP (Extended SMTP) with features like:
    - SMTP-AUTH for authentication
    - STARTTLS for encrypted connections
    - AUTH PLAIN can be used safely after encryption

Email Transmission Path

```
Client (MUA) ➞ Submission Agent (MSA) ➞ Open Relay (MTA) ➞ Mail Delivery Agent (MDA) ➞ Mailbox (POP3/IMAP)
```

- SMTP servers authenticate users to prevent spam.
- Open Relay risk: If not configured correctly, servers can be misused for mass spam.
- Protection mechanisms:
    - MSA checks email validity and origin.
    - MTA checks size and spam before storing emails.
    - Modern techniques:
        - DomainKeys Identified Mail (DKIM)
        - Sender Policy Framework (SPF)

Disadvantages of SMTP

1. No reliable delivery confirmation:
    - Only error messages returned (in English, with the original header)
2. Lack of initial user authentication:
    - Sender address can be easily spoofed
    - Leads to issues like mail spoofing and spam abuse

To interact with the SMTP server, we can use the telnet tool to initialize a TCP connection with the SMTP server.

## IMAP / POP3

Email clients interact with mail servers using protocols like **IMAP (Internet Message Access Protocol)** and **POP3 (Post Office Protocol v3)**. While POP3 is limited to basic email retrieval, IMAP provides advanced features like folder structures, server-side storage, and multi-client synchronization.

## IMAP (Internet Message Access Protocol)

- **Purpose**: Online management of emails directly on the server.
- **Advantages over POP3**:
    - Allows folder structures and multiple mailboxes.
    - Supports multiple clients and synchronization.
    - Emails remain on the server until deleted.
    - Enables browsing and managing emails on the server.

### Technical Highlights

- **Port**: 143 (unencrypted), 993 (SSL/TLS encrypted)
- **Text-based commands** (ASCII)
- **Client-server architecture** with persistent sync
- **Authentication**: Required before accessing mailboxes
- **Common Use**: Used alongside SMTP for sending mail

### IMAP Commands

| Command | Description |
| --- | --- |
| `1 LOGIN username password` | User login |
| `1 LIST "" *` | List all directories |
| `1 CREATE "INBOX"` | Create a new mailbox |
| `1 DELETE "INBOX"` | Delete a mailbox |
| `1 RENAME "ToRead" "Important"` | Rename a mailbox |
| `1 LSUB "" *` | Return active/subscribed mailboxes |
| `1 SELECT INBOX` | Select a mailbox to access messages |
| `1 UNSELECT INBOX` | Exit selected mailbox |
| `1 FETCH <ID> all` | Retrieve data from a message |
| `1 CLOSE` | Remove messages marked for deletion |
| `1 LOGOUT` | Close the connection |

---

## POP3 (Post Office Protocol v3)

- **Purpose**: Basic retrieval of emails from server to client.
- **Limitations**:
    - Does not support folders or synchronization.
    - Typically deletes emails from server after download.

### POP3 Commands

| Command | Description |
| --- | --- |
| `USER` | Identify user |
| `PASS` | Authenticate password |
| `STAT` | Show number of emails |
| `LIST` | List email IDs and sizes |
| `RETR id` | Retrieve email by ID |
| `DELE id` | Delete email by ID |
| `CAPA` | Display server capabilities |
| `RSET` | Reset email status |
| `QUIT` | Close connection |

---

## Security

- **Unencrypted by default**: Sends data in plain text.
- **Recommended**: Use **SSL/TLS** for encryption.
    - Port **993** (IMAPS), **995** (POP3S)
- **Encrypted Communication**:
    - Prevents unauthorized access and data interception.

---

## Default Configurations & Testing

- **Dovecot**: A popular open-source mail server.
    - Install with:
        
        ```bash
        sudo apt install dovecot-imapd dovecot-pop3d
        
        ```
        
    - Documentation provides details on tuning core settings.

### Default Ports

| Protocol | Plain Port | SSL/TLS Port |
| --- | --- | --- |
| IMAP | 143 | 993 |
| POP3 | 110 | 995 |

## SNMP

Simple Network Management Protocol (SNMP) was created to monitor and manage network devices such as routers, switches, servers, IoT devices, and more. In addition to monitoring, SNMP also supports remote configuration and settings adjustments.

### Key Features

- Protocol for monitoring and managing network devices.
- Supports remote configuration and control.
- Uses UDP port 161 for control commands.
- Uses UDP port 162 for traps (unsolicited server-to-client messages).
- SNMP objects require unique addresses (Object Identifiers - OIDs).

### SNMP Versions

### SNMPv1

- First version.
- Supports basic monitoring and traps.
- No built-in authentication or encryption (plain text communication).

### SNMPv2

- SNMPv2c (community-based) is most common.
- No significant security improvements over SNMPv1.
- Community string is transmitted in plain text.

### SNMPv3

- Introduces secure authentication (username/password).
- Supports encrypted transmission (pre-shared key).
- Increased complexity in configuration.

### SNMP Objects and MIB

**MIB (Management Information Base)**

- A text file listing all SNMP queryable objects in a tree hierarchy.
- Written in ASN.1-based ASCII format.
- Includes OID, name, type, access rights, and description.

**OID (Object Identifier)**

- Represents a node in a hierarchical namespace.
- Unique numerical sequence in dot notation (e.g., 1.3.6.1.2.1.1).
- Many nodes are references to sub-nodes.

**Community Strings**

- Act like passwords for SNMP data access.
- `public` is a common default read-only string.
- `private` is often used for read-write access.
- Transmitted in plain text (risk of interception).

## Tools for SNMP Footprinting

- **snmpwalk**: Queries OIDs to get info from SNMP-enabled devices.
- **onesixtyone**: Brute-forces community strings.
- **braa**: SNMP scanner.

## MySQL

MySQL is an open-source relational database management system (RDBMS) developed and supported by Oracle. It uses Structured Query Language (SQL) to manage and retrieve data. MySQL is known for its high performance, efficient storage, and client-server architecture.

**Key Features**

- Open-source and SQL-based
- High performance and space-efficient storage
- Follows client-server architecture
- Data is stored in tables organized by columns and rows
- Data often stored in .sql files (e.g., wordpress.sql)

**MySQL Clients**

Clients interact with the MySQL server to perform operations like:

- Insert
- Delete
- Modify
- Retrieve data

MySQL can handle multiple queries from various clients simultaneously and supports access over local networks or the internet.

**Common Use Cases**

- Content Management Systems (e.g., WordPress)
- Dynamic websites
- Web applications (in LAMP/LEMP stacks)

**LAMP/LEMP Stack**

- **LAMP**: Linux, Apache, MySQL, PHP
- **LEMP**: Linux, Nginx, MySQL, PHP

**Types of Data Stored**

- Content: headers, text, meta tags, forms
- User info: usernames, passwords, emails, permissions
- Site data: links, files, values, roles

Sensitive data (like passwords) is usually encrypted by PHP scripts before being stored.

**SQL Commands**

MySQL translates SQL commands into executable code. Common tasks include:

- Viewing, adding, deleting, and modifying rows
- Altering table structure
- Creating/deleting relationships and indexes
- Managing users

**Security and SQL Injection**

Improper error handling in web applications can expose MySQL to SQL injection attacks, which may reveal database structure and vulnerabilities.

**MariaDB**

MariaDB is a fork of MySQL created by its original developers after Oracle acquired MySQL AB. It is fully compatible and open-source, serving as a popular alternative.

Some of the commands we should remember and write down for working with MySQL databases are described below in the table.

| Command | Description |
| --- | --- |
| `mysql -u <user> -p<password> -h <IP address>` | Connect to the MySQL server. No space between `-p` and the password. |
| `show databases;` | Show all databases. |
| `use <database>;` | Select one of the existing databases. |
| `show tables;` | Show all available tables in the selected database. |
| `show columns from <table>;` | Show all columns in the selected table. |
| `select * from <table>;` | Show everything in the desired table. |
| `select * from <table> where <column> = "<string>";` | Search for a specific string in a column of the desired table. |

## MSSQL

Microsoft SQL (MSSQL) is Microsoft's SQL-based relational database management system. Unlike MySQL, which we discussed in the last section, MSSQL is closed source and was initially written to run on Windows operating systems. It is popular among database administrators and developers when building applications that run on Microsoft's .NET framework due to its strong native support for .NET. There are versions of MSSQL that will run on Linux and MacOS, but we will more likely come across MSSQL instances on targets running Windows.

**MSSQL Clients**

SQL Server Management Studio (SSMS) comes as a feature that can be installed with the MSSQL install package or can be downloaded & installed separately. It is commonly installed on the server for initial configuration and long-term management of databases by admins. Keep in mind that since SSMS is a client-side application, it can be installed and used on any system an admin or developer is planning to manage the database from. It doesn't only exist on the server hosting the database. This means we could come across a vulnerable system with SSMS with saved credentials that allow us to connect to the database.

**MSSQL Databases**

MSSQL has default system databases that can help us understand the structure of all the databases that may be hosted on a target server. Here are the default databases and a brief description of each:

| Command | Description |
| --- | --- |
| `mysql -u <user> -p<password> -h <IP address>` | Connect to the MySQL server. There should not be a space between `-p` and the password. |
| `show databases;` | Show all databases. |
| `use <database>;` | Select one of the existing databases. |
| `show tables;` | Show all available tables in the selected database. |
| `show columns from <table>;` | Show all columns in the selected table. |
| `select * from <table>;` | Show everything in the desired table. |
| `select * from <table> where <column> = "<string>";` | Search for a specific string in the desired table. |

## Oracle TNS

The Oracle Transparent Network Substrate (TNS) server is a communication protocol that facilitates communication between Oracle databases and applications over networks. Initially introduced as part of the Oracle Net Services software suite, TNS supports various networking protocols
between Oracle databases and client applications, such as IPX/SPX and TCP/IP protocol stacks. As a result, it has become a preferred solution for managing large, complex databases in the healthcare, finance, and retail industries. In addition, its built-in encryption mechanism ensures
the security of data transmitted, making it an ideal solution for enterprise environments where data security is paramount.

## IPMI

Intelligent Platform Management Interface (IPMI) is a set of standardized specifications for hardware-based host management systems used for system management and monitoring. It acts as an autonomous subsystem and works independently of the host's BIOS, CPU, firmware,
and underlying operating system. IPMI provides sysadmins with the ability to manage and monitor systems even if they are powered off or in an unresponsive state. It operates using a direct network connection to the system's hardware and does not require access to the operating
system via a login shell. IPMI can also be used for remote upgrades to systems without requiring physical access to the target host. IPMI is typically used in three ways:

1. Before the OS has booted to modify BIOS settings
2. When the host is fully powered down
3. Access to a host after a system failure
4. 

When not being used for these tasks, IPMI can monitor a range of different things such as system temperature, voltage, fan status, and power supplies. It can also be used for querying inventory information, reviewing hardware logs, and alerting using SNMP. The host system can be
powered off, but the IPMI module requires a power source and a LAN connection to work correctly.

The IPMI protocol was first published by Intel in 1998 and is now supported by over 200 system vendors, including Cisco, Dell, HP, Supermicro, Intel, and more. Systems using IPMI version 2.0 can be administered via serial over LAN, giving sysadmins the ability to view serial console output in band. To function, IPMI requires the following components:

- Baseboard Management Controller (BMC) - A micro-controller and essential component of an IPMI
- Intelligent Chassis Management Bus (ICMB) - An interface that permits communication from one chassis to another
- Intelligent Platform Management Bus (IPMB) - extends the BMC
- IPMI Memory - stores things such as the system event log, repository store data, and more
- Communications Interfaces - local system interfaces, serial and LAN interfaces, ICMB and PCI - Management Bus

## Linux Remote Management Protocols

In the world of Linux distributions, there are many ways to manage the servers remotely. For example, let us imagine that we are in one of many locations and one of our employees who just went to a customer in another city needs our help because of an error that he cannot
solve. Efficient troubleshooting will look difficult over a phone call in most cases, so it is beneficial if we know how to log onto the remote system to manage it.

These applications and services can be found on almost every server in the public network. It is time-saving since we do not have to be physically present at the server, and the working environment still looks the same. These protocols and applications for remote systems
management are an exciting target for these reasons. If the configuration is incorrect, we, as penetration testers, can even quickly gain access to the remote system. Therefore, we should familiarize ourselves with the most important protocols, servers, and applications for this
purpose.

### SSH

SSH (Secure Shell) is a protocol that allows two computers to establish a secure and encrypted connection over an insecure network, typically using TCP port 22. It is essential for protecting sensitive data from interception by third parties.

SSH is supported on all major operating systems. It is natively available on Linux distributions and macOS, while Windows users can install and use tools like OpenSSH. The most common implementation is OpenBSD’s OpenSSH, which is open-source.

There are two versions of the SSH protocol: SSH-1 and SSH-2. SSH-1 is considered outdated and insecure due to vulnerabilities like man-in-the-middle (MITM) attacks. SSH-2 is the current standard and offers better encryption, improved speed, and greater security.

SSH is widely used for managing remote systems via the command line or GUI. It also allows file transfers, remote command execution, and port forwarding. To connect, users must authenticate themselves to the remote system.

SSH supports several authentication methods, including password authentication, public-key authentication, host-based authentication, keyboard-interactive, challenge-response, and GSSAPI. Among these, public-key authentication is the most secure and commonly used due to its strong security and convenience.

### Rsync

Rsync is a fast and efficient tool for copying files both locally and remotely. It can transfer files within a machine or between different systems over a network. Rsync is especially known for its delta-transfer algorithm, which significantly reduces data transfer by sending only the differences between the source file and its existing version on the destination.

This makes Rsync ideal for backups and mirroring, as it identifies files that need to be transferred based on changes in size or last modified time. By default, Rsync operates over port 873, but it can also be configured to use SSH for secure file transfers by leveraging an existing SSH connection.

Rsync can sometimes be abused during penetration testing. For instance, it may be possible to list the contents of a shared folder on a remote server and download files, occasionally without authentication. In other cases, credentials might be needed. If credentials are found during a pentest, it’s worth checking Rsync services—especially for password reuse, as this might provide access to sensitive data or even lead to remote access on the target system.

## Windows Remote Management Protocols

Windows servers can be managed locally using Server Manager administration tasks on remote servers. Remote management is enabled by default starting with Windows Server 2016. Remote management is a component of the Windows hardware management features that manage server hardware locally and remotely. These features include a service that implements the WS- Management protocol, hardware diagnostics and control through baseboard management controllers, and a COM API and script objects that enable us to write applications that communicate remotely through the WS-Management protocol.
The main components used for remote management of Windows and Windows servers are the following: 

- Remote Desktop Protocol (RDP)
- Windows Remote Management (WinRM)
- Windows Management Instrumentation (WMI)

### RDP

The Remote Desktop Protocol (RDP) is a protocol developed by Microsoft for remote access to a computer running the Windows operating system. This protocol allows display and control commands to be transmitted via the GUI encrypted over IP networks. RDP works at the
application layer in the TCP/IP reference model, typically utilizing TCP port 3389 as the transport protocol. However, the connectionless UDP protocol can use port 3389 also for remote administration.

For an RDP session to be established, both the network firewall and the firewall on the server must allow connections from the outside. If Network Address Translation (NAT) is used on the route between client and server, as is often the case with Internet connections, the remote computer needs the public IP address to reach the server. In addition, port forwarding must be set up on the NAT router in the direction of the server.

RDP has handled Transport Layer Security (TLS/SSL) since Windows Vista, which means that all data, and especially the login process, is protected in the network by its good encryption. However, many Windows systems do not insist on this but still accept inadequate encryption via RDP Security. Nevertheless, even with this, an attacker is still far from being locked out because the identity-providing certificates are merely self-signed by default. This means that the client cannot distinguish a genuine certificate from a forged one and generates a certificate warning for the user.

The Remote Desktop service is installed by default on Windows servers and does not require additional external applications. This service can be activated using the Server Manager and comes with the default setting to allow connections to the service only to hosts with Network level authentication (NLA).

### WinRM

The Windows Remote Management (WinRM) is a simple Windows integrated remote management protocol based on the command line. WinRM uses the Simple Object Access Protocol (SOAP) to establish connections to remote hosts and their applications. Therefore, WinRM must be explicitly enabled and configured starting with Windows 10. WinRM relies on TCP ports 5985 and 5986 for communication, with the last port 5986 using HTTPS, as ports 80 and 443 were previously used for this task. However, since port 80 was mainly blocked for security reasons, the newer ports 5985 and 5986 are used today.

Another component that fits WinRM for administration is Windows Remote Shell (WinRS), which lets us execute arbitrary commands on the remote system. The program is even included on Windows 7 by default. Thus, with WinRM, it is possible to execute a remote command on another server.

Services like remote sessions using PowerShell and event log merging require WinRM. It is enabled by default starting with the Windows Server 2012 version, but it must first be configured for older server versions and clients, and the necessary firewall exceptions created.

### WMI

Windows Management Instrumentation (WMI) is Microsoft's implementation and also an extension of the Common Information Model (CIM), core functionality of the standardized Web-Based Enterprise Management (WBEM) for the Windows platform. WMI allows read and write access to almost all settings on Windows systems. Understandably, this makes it the most critical interface in the Windows environment for the administration and remote maintenance of Windows computers, regardless of whether they are PCs or servers. WMI is typically accessed via PowerShell, VBScript, or the Windows Management Instrumentation Console (WMIC). WMI is not a single program but consists of several programs and various databases, also known as repositories.