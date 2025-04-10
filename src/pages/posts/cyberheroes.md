---
title: "THM Cyberheroes Walkthrough"
date: "2025-04-08"

layout: ../../layouts/PostLayout.astro
description: "Detail walkthrough on tryhackme machine cyberheroes."

img_path : "/images/cyberheroes/ccc.png"
img_alt: "Insert image description here"
---

# Try Hack Me Room: CyberHeroes
![CTF](/images/cyberheroes/ch.png)

Want to be a part of the elite club of CyberHeroes? Prove your merit by finding a way to log in! Ok let’s show my skill.

## Task1: CyberHeroes
Uncover the flag!
First let’s run nmap and check what ports are open

![CTF](/images/cyberheroes/nmap.png)

We discovered 4 ports open, 22, 80, 6567 and 62078. Since port 80 is open, let’s check the website.

![CTF](/images/cyberheroes/website.png)

Now let’s find the way to login. I have no login credentials and in login form it was mentioned to show my hacking skill and become the cyberhero.

![CTF](/images/cyberheroes/login.png)

When I inspected the login page, I found that a function called authenticate()  is called on Button Click.

![CTF](/images/cyberheroes/inspect.png)

On checking the function, I got a string which uses a ReverseString Function with value. 

![CTF](/images/cyberheroes/function.png)

<b>String</b> = 54321@terceSrepuS<br>
<b>Value</b> = h3ck3rBoi

So Let’s try to Reverse it

![CTF](/images/cyberheroes/rev.png)

That reversed string is the password for username h3ck3rBoi. So let’s login.

![CTF](/images/cyberheroes/flag.png)

Boom! I really am a cyber hero.<br>
<b>ANS:</b>  flag{edb0be532c540b1a150c3a7e85d2466e}

That’s all for the CTF journal. Thank you everyone for going through it. 