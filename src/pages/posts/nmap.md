---
title: "Pentest Notes on nmap"
date: "2025-04-16"

layout: ../../layouts/PostLayout.astro
description: "nmap stands for network mapper."

img_path : "/images/nmap/theme.png"
img_alt: "theme picture"
---
## Enumeration

Enumeration is the most critical part of all. The art, the difficulty, and the goal are not to gain access to our target computer. Instead, it is identifying all of the ways we could attack a target we must find.

It is essential to understand how these services work and what syntax they use for effective communication and interaction with the different services. 

Enumeration is collecting as much information as possible. The more information we have, the easier it will be for us to find vectors of attack.

## Intro to nmap

Network Mapper (Nmap) is an open-source network analysis and security auditing tool written in C, C++, Python, and Lua.

It is designed to scan networks and identify which hosts are available on the network using raw packets, and services and applications, including the name and version, where possible. It can also identify the operating systems and versions of these hosts.

The tool is one of the most used tools by network administrators and IT security specialists. It is used to:

- Audit the security aspects of networks
- Simulate penetration tests
- Check firewall and IDS settings and configurations
- Types of possible connections
- Network mapping
- Response analysis
- Identify open ports
- Vulnerability assessment as well.

The syntax for Nmap is fairly simple and looks like this:

```
nmap <scan types> <options> <target>
```

Nmap offers many different scanning techniques, making different types of connections and using differently structured packets to send.Here we can see all the scanning techniques Nmap offers:

```
nmap --help
```

![image](/images/nmap/nmaphelp.png)

## Host Discovery

To actively discover systems on the network, we can use various Nmap host discovery options. There are many options Nmap provides to determine whether our target is alive or not. The most effective host discovery method is to use ICMP echo requests, which we will look into.

## Host & Port Scanning

After we have found out that our target is alive, we want to get a more accurate picture of the system. The information we need includes:

- Open ports and its services
- Service versions
- Information that the services provided
- Operating system

There are a total of 6 different states for a scanned port we can obtain:

| **State** | **Description** |
| --- | --- |
| **open** | Indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams, or SCTP associations. |
| **closed** | The TCP protocol indicates that the received packet contains an RST flag. This can also help determine if the target is alive. |
| **filtered** | Nmap cannot determine if the port is open or closed because either no response is returned or an error code is received. |
| **unfiltered** | Occurs during a TCP-ACK scan; the port is accessible, but its open/closed state cannot be determined. |
| **open|filtered** | If no response is received for a port, Nmap sets it to this state. It may be protected by a firewall or packet filter. |
| **closed|filtered** | Occurs only in IP ID idle scans; it is impossible to determine whether the port is closed or filtered by a firewall. |

By default, Nmap scans the top 1000 TCP ports with the SYN scan (-sS).

```
#Scanning Top 10 TCP Ports 
nmap ip --top-ports=10
```