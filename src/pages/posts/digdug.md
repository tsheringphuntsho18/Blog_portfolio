---
title: "THM DigDug Walkthrough"
date: "2025-04-08"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on tryhackme machine digdug."

img_path : "/images/DigDug/theme.png"
img_alt: "web image"
---


# Try Hack Me Room: Dig Dug
![CTF](/images/DigDug/dd.png)


### Task1: Dig Dug<br>
First let’s start the reconnaissance by doing nmap.

![CTF](/images/DigDug/nmap.png)

Only ssh port is open but we are provided with the following information;

![CTF](/images/DigDug/info.png)

When we read the instructions, we see that we have to make a special request for a givemetheflag.com domain. We were also provided with some try hack me room to tackle this room problem, let’s check it out.

![CTF](/images/DigDug/link.png)

When I read through “Passive Reconnaissance” I discover this:

![CTF](/images/DigDug/ps.png)

Our SERVER is the IP we got to attack (in my case 10.10.214.64) and our DOMAIN_NAME is givemetheflag.com. So the command is:

nslookup givemetheflag.com 10.10.214.64

![CTF](/images/DigDug/flag.png)

### Retrieve the flag from the DNS server!
<b>ANS:</b> flag{0767ccd06e79853318f25aeb08ff83e2}

Boom! We got the flag with one command. This room is easy but we have to know the command and this can be done through research. That’s it for this dig dug room, see you guys on the next try hack me room walkthrough.

