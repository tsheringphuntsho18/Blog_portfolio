---
title: "Pentest Notes on Active Directory"
date: "2025-04-30"

layout: ../../layouts/PostLayout.astro
description: "Active Directory is a maze, and group policies are the map."

img_path : "/images/ellingson/adtheme.png"
img_alt: "web image"
---

## Why?

**Why Active Directory?**

Active Directory is a system used in Windows networks to manage and organize resources like users, computers, groups, and devices in a structured and centralized way.

**Key Functions:**

- **Authentication:** Verifies who you are.
- **Authorization:** Decides what you can do once you're in.

**Structure:**

- AD is hierarchical and distributed, meaning it can span many systems while staying organized.
- It stores information in a read-only database that all users in the domain can access to some extent.

AD is built to support older systems, so it’s not always "secure by default.". If not set up properly, AD can expose the network to serious security risks. Attackers can use vulnerabilities in AD to move across the network or elevate their access.

**Why Even Basic Users Can Be Dangerous**

- AD is exposed to All Users: Even users with no special privileges can see most of the AD setup.
- Information Gathering: Any user can look for weak spots or misconfigurations to exploit.
- Standard Users Can Launch Attacks: Some attacks require only a basic domain account—no admin access needed.

**To keep AD and the whole network safe, organizations should:**

- Follow the principle of least privilege (give users only the access they truly need).
- Use network segmentation (separate sensitive areas).
- Apply defense-in-depth strategies (layered security).
- Regularly audit and harden AD configurations.

**Example Attack: noPac**

- A major vulnerability (called noPac) was discovered in December ****2021.
- It showed how attackers could gain high-level access using just a standard user account.

Active Directory makes information easy to find and use for administrators and users. AD is highly scalable, supports millions of objects per domain, and allows the creation of additional domains as an organization grows.

**Why AD Matters**

- Used by 95% of Fortune 500 companies, Active Directory is a core component in most enterprise networks.
- Because of its wide usage, AD is a prime target for attackers.
- Even a simple phishing attack that gives an attacker a standard domain user account can lead to domain mapping and further exploitation.

Ransomware operators, like the Conti group, have heavily targeted AD environments.

- Conti has been used in over 400 attacks globally, exploiting AD vulnerabilities such as:
    - PrintNightmare (CVE-2021-34527)
    - Zerologon (CVE-2020-1472)
- These attacks use AD flaws to escalate privileges and move laterally within networks

Many open-source tools are available to enumerate and attack AD. However, tools are only as powerful as the knowledge of the person using them. To use these tools effectively, you need to deeply understand:

- How AD is structured
- How permissions and rights are granted
- Common misconfigurations and flaws

---

## Active Directory Structure

- **Definition**: Active Directory (AD) is a directory service developed by Microsoft for Windows network environments.
- **Structure**:
    - Distributed and hierarchical.
    - Allows centralized management of resources.
- **Manages**:
    - Users
    - Computers
    - Groups
    - Network devices
    - File shares
    - Group policies
    - Servers & workstations
    - Trusts
- **Core Functions**:
    - **Authentication**: Verifying user identity.
    - **Authorization**: Granting access to resources.
- **Active Directory Domain Services (AD DS)**:
    - Stores and organizes directory data (e.g., usernames, passwords).
    - Provides access to users and administrators.
- **History**:
    - Introduced with **Windows Server 2000**.
    - Designed to be **backward-compatible**, but not always **secure by default**.
- **Security & Management**:
    - Increasingly targeted in cyber attacks.
    - Complex to manage, especially in **large environments**.
    - Susceptible to **misconfiguration**.
- **Security Risks**:
    - AD flaws and misconfigurations can be exploited to:
        - Gain **internal access** (initial foothold).
        - Perform **lateral and vertical movement** within the network.
        - Access **unauthorized resources** (e.g., databases, file shares, source code).
- **AD as a Database**:
    - Functions as a **centralized database** accessible to all domain users.
    - Accessibility applies **regardless of privilege level**.
- **Enumeration by Basic Users**:
    - Even low-privileged users can enumerate a significant portion of AD objects, such as:
        - User accounts
        - Group memberships
        - Computers
        - Organizational Units (OUs)
        - Group Policy Objects (GPOs)
        - Service Principal Names (SPNs)
        - Trust relationships
    
    **Hierarchical Tree Structure**:
    
    - **Forest** (top level):
        - A forest is the **security boundary** for all objects.
        - Can contain **multiple domains**.
    - **Domains**:
        - Logical groupings of users, computers, and resources.
        - May include **child or sub-domains**.
    - **Organizational Units (OUs)**:
        - Containers within domains to organize users, groups, computers.
        - Built-in OUs include: **Domain Controllers, Users, Computers**.
        - **Custom OUs** can be created.
        - Allow assignment of **Group Policies (GPOs)**.
    - **Objects**:
        - Users, Computers, Groups, etc., reside in OUs or domains.
    
    **Example AD Structure**:
    
    ```
    INLANEFREIGHT.LOCAL/
    ├── ADMIN.INLANEFREIGHT.LOCAL
    │   ├── GPOs
    │   └── OU
    │       └── EMPLOYEES
    │           ├── COMPUTERS
    │           │   └── FILE01
    │           ├── GROUPS
    │           │   └── HQ Staff
    │           └── USERS
    │               └── barbara.jones
    ├── CORP.INLANEFREIGHT.LOCAL
    └── DEV.INLANEFREIGHT.LOCAL
    ```
    

---

## Active Directory Terminology

Let’s define some key terminology that we will use in AD.

**1. Object**

- Any resource in AD (e.g., users, computers, OUs, printers).

**2. Attributes**

- Define characteristics of objects (e.g., `displayName`, `givenName`).
- Used in LDAP queries.

**3. Schema**

- The AD "blueprint"; defines object types and attributes.
- Classes like `user` or `computer` define templates; actual objects are instances.

**4. Domain**

- Logical group of objects (users, OUs, groups, etc.).
- Like a city; can work independently or with trusts.

**5. Forest**

- A collection of domains.
- The top container in AD, like a country.

**6. Tree**

- A hierarchy of domains starting from a root.
- Domains in a tree share a common namespace and global catalog.

**7. Container vs. Leaf**

- **Container**: Holds other objects (e.g., OUs).
- **Leaf**: End objects (e.g., users, computers).

**8. GUID (Global Unique Identifier)**

- 128-bit unique identifier for each object.
- Stored in `ObjectGUID` attribute; remains unchanged.

**9. Security Principals**

- Authenticated entities: users, computers, processes.
- Managed by AD or local Security Accounts Manager (SAM).

**10. SID (Security Identifier)**

- Unique to users/groups.
- Used in access tokens, cannot be reused once deleted.

**11. DN (Distinguished Name)**

- Full path to an object (e.g., `cn=bjones, ou=IT...`).

**12. RDN (Relative Distinguished Name)**

- The unique name of the object at its level (e.g., `bjones`).

**13. sAMAccountName**

- Pre-Windows 2000 logon name (e.g., `bjones`), ≤ 20 characters.

**14. userPrincipalName (UPN)**

- Modern logon name format: `user@domain.local`.

**15. FSMO Roles**

- Prevent conflicts in multi-DC environments.
- Five roles:
    - **Forest-wide**: Schema Master, Domain Naming Master
    - **Domain-wide**: RID Master, PDC Emulator, Infrastructure Master

**16. Global Catalog**

- Holds full info of local domain + partial of others.
- Aids in authentication and searching across forests.

**17. RODC (Read-Only Domain Controller)**

- Cannot write or replicate changes.
- Used for security in branch offices.

**18. Replication**

- Synchronizes changes between Domain Controllers.
- Managed by KCC (Knowledge Consistency Checker).

**19. SPN (Service Principal Name)**

- Uniquely identifies a service instance for Kerberos.

**20. GPO (Group Policy Object)**

- Policy settings applied to users/computers.
- Can be applied at domain/OU levels.

**21. ACL (Access Control List)**

- List of ACEs that define permissions for an object.

**22. ACE (Access Control Entry)**

- Entry that grants/denies/audits access for a trustee.

**23. DACL (Discretionary ACL)**

- Lists who can or can't access an object.
- Absence = full access; empty = no access.

**24. SACL (System ACL)**

- Logs access attempts for audit purposes.

**25. FQDN (Fully Qualified Domain Name)**

- Full DNS name: `[hostname].[domain].[tld]`
- E.g., `DC01.INLANEFREIGHT.LOCAL`.

**26. Tombstone**

- Deleted objects held temporarily before permanent deletion.
- `isDeleted` = TRUE; default retention = 60 or 180 days.

**27. SYSVOL**

- Stores public domain files like:
    - Group Policy templates (`GPT`)
    - Logon/logoff scripts
- Replicated to all Domain Controllers via **FRS** or **DFS-R**
- Common target for GPO manipulation (e.g., logon script persistence)

**28. AdminSDHolder**

- Container object managing ACLs for **protected groups** (e.g., Domain Admins)
- **SDProp** runs hourly (by default) on the **PDC Emulator** to reapply secure ACLs
- Prevents privilege persistence by resetting unauthorized ACL changes

**29. dsHeuristics**

- Configurable string attribute on the **Directory Service** object
- Can be used to **exclude** groups from being treated as "protected"
- Misconfiguration here can weaken security for privileged groups

**30. adminCount**

- Attribute on user objects:
    - `1`: user is **protected** by AdminSDHolder
    - `0` or unset: user is **not protected**
- Attackers often search for `adminCount=1` to find high-value targets

**31. ADUC (Active Directory Users and Computers)**

- GUI tool for managing users, groups, and OUs
- Limited to standard tasks compared to advanced tools like ADSI Edit

32. **ADSI Edit**

- GUI editor for AD at the **attribute level**
- Used for:
    - Editing `adminCount`, `sIDHistory`, `servicePrincipalName`, etc.
    - Removing orphaned objects
- Powerful but risky — missteps can break AD

33. **sIDHistory**

- Stores **old SIDs** of migrated accounts
- Helps retain access permissions after migration
- Can be abused in **SID injection attacks** if **SID filtering** isn't applied

34. **NTDS.DIT**

- Core **AD database file**
- Location: `C:\Windows\NTDS\ntds.dit`
- Contains:
    - All user accounts
    - Group memberships
    - **Password hashes**
- If exfiltrated, can be used for:
    - **Pass-the-Hash (PtH)**
    - Offline cracking with **Hashcat**

35. **MSBROWSE**

- Legacy **NetBIOS browsing** mechanism
- Identifies the **Master Browser** of a Windows LAN
- Tools: `nbtstat -A`, `nltest`
- **Deprecated** — replaced by **SMB/CIFS** in modern systems

---

## Active Directory Objects

An object can be defined as ANY resource present within an Active Directory environment such as OUs, printers, users, domain controllers.

**Users**

- **Definition**: Represents individuals within the organization’s AD environment.
- **Type**: Leaf object (cannot contain other objects).
- **Attributes**: Includes display name, email, login time, password change date, etc. There are **over 800 possible attributes** depending on the environment.
- **Security**: A **security principal**, meaning it has a **SID** and **GUID**.
- **Importance for Attackers**: Low-privileged user accounts can be a stepping stone for attackers to enumerate other domain resources.

**Contacts**

- **Definition**: Represents external users (e.g., vendors, customers).
- **Type**: Leaf object (cannot contain other objects).
- **Attributes**: Typically includes name, email, phone number, etc.
- **Security**: Not a security principal (no SID, only a GUID).

**Printers**

- **Definition**: Represents printers accessible within the AD network.
- **Type**: Leaf object (cannot contain other objects).
- **Attributes**: Printer name, driver information, port number, etc.
- **Security**: Not a security principal (no SID, only a GUID).

**Computers**

- **Definition**: Any computer (workstation/server) joined to the AD network.
- **Type**: Leaf object (cannot contain other objects).
- **Attributes**: SID, GUID.
- **Security**: A **security principal**. These are key targets for attackers, as full access to a computer grants domain-like rights.

**Shared Folders**

- **Definition**: Represents shared folders on a computer within the AD environment.
- **Type**: Not a security principal (only has a GUID).
- **Attributes**: Folder name, location, access rights.
- **Security**: Can have strict access controls, determining who can access the folder.

**Groups**

- **Definition**: A container object that holds other objects such as users, computers, and even other groups.
- **Type**: Security principal (has a SID and GUID).
- **Security**: Used to manage access control, groups make it easier to assign permissions to multiple users at once.
- **Nested Groups**: Groups within groups, which can result in unintended permission inheritance (often leveraged during penetration tests).

**Organizational Units (OUs)**

- **Definition**: A container used for grouping similar objects for easier management.
- **Purpose**: Administrative delegation (e.g., setting permissions or policies for specific departments).
- **Attributes**: Name, members, security settings.
- **Use Cases**: Can manage Group Policy settings and delegate specific rights like password resets within an OU.

**Domain**

- **Definition**: The overall structure of an AD network.
- **Attributes**: Policies like password policy and user access settings.
- **Security**: Domains contain user objects, groups, OUs, etc.

**Domain Controllers**

- **Definition**: Servers that authenticate users and enforce security policies.
- **Role**: Verifies user access and enforces policies.
- **Importance**: These are crucial to the AD environment and hold all information about objects in the domain.

**Sites**

- **Definition**: Logical grouping of computers across one or more subnets connected by high-speed links.
- **Purpose**: Makes replication across domain controllers more efficient.

**Built-in**

- **Definition**: A container that holds default groups created when an AD domain is established.
- **Purpose**: Contains groups such as Domain Admins, Enterprise Admins, etc.

**Foreign Security Principals (FSP)**

- **Definition**: Placeholder objects representing security principals from external forests.
- **Purpose**: Created when an external user or group is added to a local group in the AD domain.
- **Attributes**: Holds the SID of the foreign object for resolving its name.

---

## Active Directory Functionality

As mentioned before, there are five Flexible Single Master Operation (FSMO) roles. These roles can be defined as follows:

| **Role** | **Description** |
| --- | --- |
| **Schema Master** | Manages the read/write copy of the AD schema, which defines all attributes that can apply to an object in AD. |
| **Domain Naming Master** | Manages domain names and ensures that two domains of the same name are not created in the same forest. |
| **Relative ID (RID) Master** | Assigns blocks of RIDs to other DCs within the domain for new objects. Helps ensure that multiple objects are not assigned the same SID. |
| **PDC Emulator** | The authoritative DC in the domain, responds to authentication requests, password changes, and manages Group Policy Objects (GPOs). Also maintains time within the domain. |
| **Infrastructure Master** | Translates GUIDs, SIDs, and DNs between domains. Used in multi-domain forests for communication. If not functioning properly, ACLs will show SIDs instead of fully resolved names. |

Depending on the organization, these roles may be assigned to specific DCs or as defaults each time a new DC is added. Issues with FSMO roles will lead to authentication and authorization difficulties within a domain.

**Domain and Forest Functional Levels**

Microsoft introduced functional ****levels in Active Directory Domain Services (AD DS) to define the available features and capabilities at both the domain and forest levels. These functional levels also dictate which Windows ****Server ****operating ****systems can run as Domain Controllers in a given domain or forest.

| **Domain Functional Level** | **Features Available** | **Supported Domain Controller Operating Systems** |
| --- | --- | --- |
| **Windows 2000 native** | Universal groups for distribution and security groups, group nesting, group conversion (between security and distribution and security groups), SID history. | Windows Server 2008 R2, Windows Server 2008, Windows Server 2003, Windows 2000 |
| **Windows Server 2003** | Netdom.exe domain management tool, lastLogonTimestamp attribute introduced, well-known users and computers containers, constrained delegation, selective authentication. | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008, Windows Server 2003 |
| **Windows Server 2008** | Distributed File System (DFS) replication support, AES 128 and AES 256 support for the Kerberos protocol, Fine-grained password policies. | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008 |
| **Windows Server 2008 R2** | Authentication mechanism assurance, Managed Service Accounts. | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2 |
| **Windows Server 2012** | KDC support for claims, compound authentication, and Kerberos armoring. | Windows Server 2012 R2, Windows Server 2012 |
| **Windows Server 2012 R2** | Extra protections for members of the Protected Users group, Authentication Policies, Authentication Policy Silos. | Windows Server 2012 R2 |
| **Windows Server 2016** | Smart card required for interactive logon, new Kerberos features, new credential protection features. | Windows Server 2019 and Windows Server 2016 |

Forest functional levels have introduced a few key capabilities over the years:

| **Version** | **Capabilities** |
| --- | --- |
| **Windows Server 2003** | Introduction of forest trust, domain renaming, read-only domain controllers (RODC), and more. |
| **Windows Server 2008** | All new domains added to the forest default to the Server 2008 domain functional level. No additional new features. |
| **Windows Server 2008 R2** | Active Directory Recycle Bin provides the ability to restore deleted objects when AD DS is running. |
| **Windows Server 2012** | All new domains added to the forest default to the Server 2012 domain functional level. No additional new features. |
| **Windows Server 2012 R2** | All new domains added to the forest default to the Server 2012 R2 domain functional level. No additional new features. |
| **Windows Server 2016** | Privileged access management (PAM) using Microsoft Identity Manager (MIM). |

**Trusts**

A trust is used to establish forest-forest or domain-domain authentication, allowing users to access resources in (or administer) another domain outside of the domain their account resides in. A trust creates a link between the authentication systems of two domains.

| **Trust Type** | **Description** |
| --- | --- |
| **Parent-child** | Domains within the same forest. The child domain has a two-way transitive trust with the parent domain. |
| **Cross-link** | A trust between child domains to speed up authentication. |
| **External** | A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering. |
| **Tree-root** | A two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest. |
| **Forest** | A transitive trust between two forest root domains. |

Trusts can be transitive or non-transitive.

- A transitive trust means that trust is extended to objects that the child domain trusts.
- In a non-transitive trust, only the child domain itself is trusted.

Trusts can be set up to be one-way or two-way (bidirectional).

- In bidirectional trusts, users from both trusting domains can access resources.
- In a one-way trust, only users in a trusted domain can access resources in a trusting domain, not vice-versa. The direction of trust is opposite to the direction of access.

---

## Auth LDAP Kerberos

While Windows operating systems use a variety of protocols to communicate, Active Directory specifically requires Lightweight Directory Access Protocol (LDAP), Microsoft's version of Kerberos, DNS for authentication and communication, and MSRPC which is the Microsoft implementation
of Remote Procedure Call (RPC), an interprocess communication technique used for client-server model-based applications.

**1. Kerberos (Port 88 TCP/UDP)**

- Default authentication protocol for AD since Windows 2000.
- Based on **ticketing system**, not passwords—protects credentials in transit.
- Components:
    - **AS-REQ** / **AS-REP**: Authentication Service for TGT.
    - **TGS-REQ** / **TGS-REP**: Service Ticket for specific services.
    - **AP-REQ**: Access request with the TGS.
- Domain Controllers act as **Key Distribution Centers (KDCs)**.
- Tickets are encrypted using:
    - User’s password (TGT)
    - Service account’s NTLM hash (TGS)
- Stateless authentication: doesn't track previous sessions.

**2. DNS (Port 53 TCP/UDP)**

- Resolves hostnames to IPs and vice versa.
- Critical for locating Domain Controllers via **SRV records**.
- Used in **Forward Lookup** (name ➜ IP) and **Reverse Lookup** (IP ➜ name).
- Employs **Dynamic DNS** to auto-update DNS records, reducing admin overhead.
- Example tool: `nslookup`

**3. LDAP (Port 389), LDAPS (Port 636)**

- Protocol for querying and modifying AD directory services.
- Works like HTTP to Apache: LDAP is the protocol, AD is the server.
- **Authentication types**:
    - **Simple**: Username/password sent as BIND request (can be insecure).
    - **SASL**: Uses Kerberos or another secure auth service.
- AD data (users, groups, permissions) accessed via LDAP.
- Security Note: Use TLS to avoid credentials sent in plaintext.

**4. MSRPC (Varied Ports)**

Microsoft’s RPC used for managing AD and communication between systems.

- **Key Interfaces**:
    - `lsarpc`: Local Security Authority (LSA) - domain policy management.
    - `netlogon`: Handles authentication services across domain.
    - `samr`: Manages user/group accounts—can be misused for domain recon (e.g., BloodHound).
    - `drsuapi`: Handles AD replication; abused to extract NTDS.dit file (contains password hashes).

---

## NTLM Auth

**Hash Protocol Comparison**

| Hash/Protocol | Cryptographic Technique | Mutual Authentication | Message Type | Trusted Third Party |
| --- | --- | --- | --- | --- |
| NTLM | Symmetric key cryptography | No | Random number | Domain Controller |
| NTLMv1 | Symmetric key cryptography | No | MD4 hash, random number | Domain Controller |
| NTLMv2 | Symmetric key cryptography | No | MD4 hash, random number | Domain Controller |
| Kerberos | Symmetric key cryptography & asymmetric cryptography | Yes | Encrypted ticket using DES, MD5 | Domain Controller / KDC |

### **LM**

- **Introduced**: 1987 on OS/2, later used in early Windows systems.
- **Storage Location**:
    - `SAM` database (local)
    - `NTDS.DIT` database (Domain Controllers)
- **Status**: Disabled by default since Windows Vista / Server 2008, but still found in legacy systems.

**Hashing Mechanism**:

- Passwords are:
    - **Limited to 14 characters**
    - **Not case sensitive** (converted to uppercase)
    - **Padded with NULLs** if under 14 characters
- Split into **two 7-character chunks**
- Each chunk creates a **DES key**
- Encrypted using the string **`KGS!@#$%`**
- Resulting in two 8-byte ciphertexts → concatenated to form **LM hash**

**Security Weaknesses**:

- Small keyspace (only 69 characters)
- Can be cracked quickly using **GPU tools like Hashcat**
- Only 7 characters need to be brute-forced at a time
- For passwords ≤7 characters, second half of hash is static/predictable

**Mitigation**:

- LM hash usage can be **disabled via Group Policy**
- Modern systems **do not rely on LM hashes**

**Example LM Hash**: `299bd128c1101fd6`

### **NTHash (NTLM)**

- **Used in**: Modern Windows systems (still supported, though Kerberos is preferred in domains).
- **Authentication Protocol**: Challenge-response based, involving three messages:
    1. `NEGOTIATE_MESSAGE` (Client → Server)
    2. `CHALLENGE_MESSAGE` (Server → Client)
    3. `AUTHENTICATE_MESSAGE` (Client → Server)

**Hash Storage Locations**:

- Local: **`SAM` database**
- Domain Controllers: **`NTDS.DIT` file**

**Password Hashing**:

- NTLM uses:
    - LM hash (legacy; optional)
    - **NT hash**: Computed as
        
        ➤ `MD4(UTF-16-LE(password))`
        
- Supports full **Unicode charset** (65,536 characters)
- Older systems (Windows NT4 to XP, 2003) stored **both LM and NTLM** hashes by default

**Security Weaknesses**:

- **Susceptible to brute-force attacks** (even offline):
    - 8-character NTLM passwords can be cracked in **<3 hours with GPU**
    - **Longer passwords** still vulnerable to **dictionary + rules attacks**
- **Vulnerable to pass-the-hash (PtH)**:
    - An attacker can **authenticate using only the NTLM hash** without knowing the actual password
    - Common in **lateral movement** and **post-exploitation** in Windows networks

### NTLMv1 (Net-NTLMv1)

The NTLM protocol performs a challenge/response between a server and client using the NT hash. NTLMv1 uses both the NT and the LM hash, which can make it easier to "crack" offline after capturing a hash using a tool such as Responder or via an NTLM relay attack (both of which are
out of scope for this module and will be covered in later modules on Lateral Movement). The protocol is used for network authentication, and the Net-NTLMv1 hash itself is created from a challenge/response algorithm. The server sends the client an 8-byte random number (challenge), and the client returns a 24-byte response. These hashes can NOT be used for pass-the-hash attacks. 

### NTLMv2 (Net-NTLMv2)

The NTLMv2 protocol was first introduced in Windows NT 4.0 SP4 and was created as a stronger alternative to NTLMv1. It has been the default in Windows since Server 2000. It is hardened against certain spoofing attacks that NTLMv1 is susceptible to. NTLMv2 sends two responses to the 8-
byte challenge received by the server. These responses contain a 16-byte HMAC-MD5 hash of the challenge, a randomly generated challenge from the client, and an HMAC-MD5 hash of the user's credentials. A second response is sent, using a variable-length client challenge including the
current time, an 8-byte random value, and the domain name.

### Domain Cached Credentials (MSCache2)

- **Purpose**: Allows domain-joined machines to authenticate domain users locally when the Domain Controller (DC) is unreachable (e.g., due to network issues).
- **Hash Storage**:
    - Stored in the Windows Registry:
        
        `HKEY_LOCAL_MACHINE\SECURITY\Cache`
        
    - By default, **last 10 successful domain login hashes** are cached.
- **Hash Versions**:
    - **MS Cache v1** and **MS Cache v2 (DCC2)**
    - DCC2 format example:
        
        `$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f`
        
- **Security Considerations**:
    - Cannot be used in **pass-the-hash** attacks.
    - Hashes are **very slow to crack**, even with powerful GPUs.
    - Cracking is only practical with **very weak passwords** or highly **targeted wordlists**.
    - These hashes can only be obtained after gaining **local administrator** access.
- **Penetration Testing Implications**:
    - Important to recognize and differentiate hash types during AD assessments.
    - Understand when it is feasible to attack (e.g., LM/NTLM) vs. when it is impractical (e.g., DCC with strong passwords).
    - Cracking DCC hashes without clear context or strategy is usually a waste of time.

---

## User and Machine Accounts

User accounts are essential in both local systems and Active Directory (AD) environments, enabling users or services to log in and access resources based on assigned permissions. Upon login, an access token is generated that contains the user's identity and group memberships, which is used to authorize access to files, applications, and other resources. Managing users through group assignments simplifies privilege management and enhances administrative efficiency. AD environments typically provide at least one account per user, but some users—such as IT administrators—may have multiple accounts. In addition to user accounts, service accounts are often provisioned to support applications and background services. Large organizations frequently maintain numerous active and inactive accounts, including those for seasonal staff or former employees, often stored in designated organizational units (OUs) like "FORMER EMPLOYEES" for auditing purposes. Proper management of these accounts is critical to maintaining security and operational integrity.

### Local Accounts

Local accounts are created and stored locally on individual systems (servers or workstations). They are security principals but have access limited to the specific host where they are created. These accounts are not valid across a domain and are commonly used to control access and run services locally.

**Key Characteristics:**

- Rights can be assigned directly or through local group membership.
- These rights are host-specific and do not apply domain-wide.
- Default local accounts are created during Windows setup for administrative or system purposes.

**Default Local Accounts:**

1. Administrator
    - SID: `S-1-5-domain-500`.
    - Created during Windows installation with full control over the system.
    - Cannot be deleted or locked, but can be renamed or disabled.
    - Disabled by default on Windows 10 and Server 2016. A different admin account is created instead.
2. Guest
    - Used for temporary access for users without a user account.
    - Disabled by default, with a blank password.
    - Has limited privileges; recommended to keep disabled due to security risks.
3. SYSTEM (NT AUTHORITY\SYSTEM)
    - Internal service account used by the OS for background operations.
    - Highest privilege level on a Windows system.
    - No profile or visibility in User Manager; cannot be added to groups.
    - Runs many Windows processes and services.
4. Network Service
    - Used by the Service Control Manager (SCM) to run services.
    - Presents machine credentials to remote systems.
    - Has limited privileges locally.
5. Local Service
    - Also used by SCM to run services.
    - Has minimal local privileges.
    - Presents anonymous credentials to network services.

### Domain Users

Domain users differ from local users in that they are granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on the permissions granted to their user account or the group that account is a member of. Domain user accounts
can log in to any host in the domain, unlike local users. For more information on the many different Active Directory account types, check out this link. One account to keep in mind is the KRBTGT account, however. This is a type of local account built into the AD infrastructure. This account
acts as a service account for the Key Distribution service providing authentication and access for domain resources. This account is a common target of many attackers since gaining control or access will enable an attacker to have unconstrained access to the domain. It can be leveraged
for privilege escalation and persistence in a domain through attacks such as the Golden Ticket attack.

### User Naming Attributes

Security in Active Directory can be improved using a set of user naming attributes to help identify user objects like logon name or ID. The following are a few important Naming Attributes in AD:

| Attribute | Description |
| --- | --- |
| **UserPrincipalName (UPN)** | The primary logon name for the user; typically matches the user's email address. |
| **ObjectGUID** | A globally unique identifier for the user object; remains unchanged even if the user is removed. |
| **SAMAccountName** | Logon name compatible with older versions of Windows clients and servers. |
| **objectSID** | The Security Identifier (SID) used to identify the user and their group memberships. |
| **sIDHistory** | Stores previous SIDs if the user is migrated from another domain; used for domain migration support. |

### Domain-joined vs. Non-Domain-joined Machines

- **Domain-Joined Hosts:**
    - Managed centrally through a **Domain Controller (DC)**.
    - Use **Group Policy** for consistent configuration, updates, and security enforcement.
    - Enable **easier resource sharing** and user login across any domain-joined system.
    - Common in **enterprise environments** where central control and scalability are necessary.
- **Non-Domain-Joined (Workgroup) Hosts:**
    - Operate independently, without DC management.
    - **Users manage their own settings**; no centralized control.
    - Suitable for **home networks or small businesses** on a local LAN.
    - User accounts are **local only** and cannot be used on other machines.
- **Machine Account (NT AUTHORITY\SYSTEM):**
    - In AD, SYSTEM-level access has privileges similar to a **standard domain user**.
    - SYSTEM access on a domain-joined host allows **read access across the domain**.
    - Gaining SYSTEM access (e.g., through **RCE or privilege escalation**) is a **valuable entry point** for AD enumeration and attacks.
    - SYSTEM access is often **underestimated**, but it enables gathering of domain information even without user credentials.

---

## Active Directory Groups

In Active Directory, groups are crucial for managing access and rights by grouping similar users together, allowing mass assignment of permissions and resource access. They are key targets for attackers and penetration testers since the rights granted to group members may not always be obvious, and improper configuration can lead to excessive privileges. While there are many built-in groups in AD, organizations often create custom groups to manage access effectively. However, the sheer number of groups can become overwhelming, potentially leading to unintended access if not carefully managed. Regular audits are essential to ensure that group memberships are appropriate and that no excessive privileges are granted. It's also important to understand the distinction between groups and Organizational Units (OUs). While OUs help in organizing users, groups, and computers for easier management and application of Group Policy, groups are mainly used to assign permissions to resources. OUs can also delegate specific administrative tasks like resetting passwords or unlocking accounts without granting broader admin rights through group membership.

**Types of Groups**

In Active Directory, groups are used to organize users, computers, and contact objects for easier administration, especially when managing permissions and resource assignments. Rather than assigning permissions individually to users, a system administrator can assign permissions to a group, and all members of that group will inherit those permissions. For example, instead of granting 50 members of a department access to a shared drive one by one, an admin can create a group, add the department members to it, and assign the necessary permissions to the group. This method simplifies permission management, improves auditability, and makes it easier to modify or revoke permissions. If any user’s permissions need to be changed, they can simply be removed from the group without affecting others.

Groups in Active Directory are defined by two main characteristics:

1. **Group Type**: Defines the group’s purpose. There are two types of groups:
    - **Security Groups**: Used to assign permissions to resources.
    - **Distribution Groups**: Used for email distribution lists and not for assigning permissions.
2. **Group Scope**: Defines how the group can be used within the domain or forest, determining the extent to which the group can be applied across different levels of the AD structure.

By organizing users into groups, administrators can easily manage resource access and perform audits with greater efficiency.

The Security groups type is primarily for ease of assigning permissions and rights to a collection of users instead of one at a time. They simplify management and reduce overhead when assigning permissions and rights for a given resource. All users added to a security group will inherit any
permissions assigned to the group, making it easier to move users in and out of groups while leaving the group's permissions unchanged.

The Distribution groups type is used by email applications such as Microsoft Exchange to distribute messages to group members. They function much like mailing lists and allow for auto-adding emails in the "To" field when creating an email in Microsoft Outlook. This type of group cannot be used
to assign permissions to resources in a domain environment.

**Group Scopes**

When creating a group in Active Directory, there are three possible group scopes that define how the group can be used and where it can grant permissions. The three group scopes are:

1. **Domain Local Group**:
    - **Scope**: Can only be used to manage permissions for resources within the domain where it was created.
    - **Characteristics**:
        - Can contain users from other domains.
        - Cannot be used in other domains.
        - Can be nested into other domain local groups but **NOT** global groups.
2. **Global Group**:
    - **Scope**: Can be used to grant access to resources in other domains.
    - **Characteristics**:
        - Can only contain accounts from the domain in which it was created.
        - Can be added to both global groups and domain local groups.
3. **Universal Group**:
    - **Scope**: Can manage resources across multiple domains within the same forest and can have permissions on any object within the forest.
    - **Characteristics**:
        - Can contain users from any domain within the forest.
        - Stored in the **Global Catalog (GC)**.
        - Changes to membership in universal groups trigger **forest-wide replication**, which can result in network overhead.
        - It is recommended to nest global groups within universal groups to reduce replication traffic.

Understanding group scopes is crucial for setting up efficient Active Directory permissions and maintaining optimal replication across the network. It is also important to consider the potential impact of universal group membership changes, which can trigger extensive replication within the forest.

Group scopes can be changed, but there are a few caveats:

- A Global Group can only be converted to a Universal Group if it is NOT part of another Global Group.
- A Domain Local Group can only be converted to a Universal Group if the Domain Local Group does NOT contain any other Domain Local Groups as members.
- A Universal Group can be converted to a Domain Local Group without any restrictions.
- A Universal Group can only be converted to a Global Group if it does NOT contain any other Universal Groups as members.

---

## Active Directory Rights and Privileges

Rights and privileges are critical components of Active Directory (AD) management, and improper handling of these can lead to security vulnerabilities or exploitation by attackers. Understanding the difference between them is essential:

- **Rights**: Typically assigned to users or groups, rights deal with permissions to access specific objects, such as files or directories.
- **Privileges**: Grant a user permission to perform actions, such as running a program, shutting down a system, or resetting passwords. Privileges are usually granted individually or through group membership.

Windows computers utilize a concept called **User Rights Assignment**, which refers to privileges granted to users, even though it is referred to as rights. Understanding the distinction between rights and privileges, and how they function in an AD environment, is fundamental to maintaining secure access controls.

**Built-in AD Groups**

The most common built-in groups are listed below.

| **Group Name** | **Description** |
| --- | --- |
| **Account Operators** | Members can create and modify most types of accounts, including those of users, local groups, and global groups, and log in locally to domain controllers. Cannot manage Admin accounts. |
| **Administrators** | Members have full and unrestricted access to a computer or an entire domain if they are in this group on a Domain Controller. |
| **Backup Operators** | Members can back up and restore all files on a computer. They can log on to DCs locally and make shadow copies of the SAM/NTDS database. |
| **DnsAdmins** | Members have access to network DNS information. Created if DNS server role is or was installed on a domain controller. |
| **Domain Admins** | Members have full access to administer the domain and are members of the local administrator's group on all domain-joined machines. |
| **Domain Computers** | Contains all computers created in the domain (aside from domain controllers). |
| **Domain Controllers** | Contains all DCs within a domain. New DCs are added to this group automatically. |
| **Domain Guests** | Includes the domain's built-in Guest account. Members have a domain profile when signing onto a domain-joined computer as a local guest. |
| **Domain Users** | Contains all user accounts in a domain. New user accounts are automatically added to this group. |
| **Enterprise Admins** | Provides complete configuration access within the domain. Members can make forest-wide changes, such as adding a child domain or creating a trust. |
| **Event Log Readers** | Members can read event logs on local computers. Group is only created when a host is promoted to a domain controller. |
| **Group Policy Creator Owners** | Members create, edit, or delete Group Policy Objects in the domain. |
| **Hyper-V Administrators** | Members have complete and unrestricted access to all features in Hyper-V. Considered Domain Admins for virtual DCs. |
| **IIS_IUSRS** | Built-in group used by Internet Information Services (IIS), beginning with IIS 7.0. |
| **Pre–Windows 2000 Compatible Access** | Exists for backward compatibility for computers running Windows NT 4.0 and earlier. Can lead to flaws allowing network read access without a valid AD username and password. |
| **Print Operators** | Members can manage, create, share, and delete printers connected to domain controllers. Members can log on to DCs locally and escalate privileges. |
| **Protected Users** | Members have additional protections against credential theft and tactics such as Kerberos abuse. |
| **Read-only Domain Controllers** | Contains all Read-only domain controllers in the domain. |
| **Remote Desktop Users** | Grants permission to connect to a host via Remote Desktop (RDP). This group cannot be renamed, deleted, or moved. |
| **Remote Management Users** | Grants users remote access to computers via Windows Remote Management (WinRM). |
| **Schema Admins** | Members can modify the Active Directory schema. Only exists in the root domain of an AD forest. |
| **Server Operators** | Exists on domain controllers. Members can modify services, access SMB shares, and back up files on domain controllers. By default, no members. |

**User Rights Assignmen**

Depending on their current group membership and other factors such as privileges that administrators can assign via Group Policy (GPO), users can have various rights assigned to their account. The Microsoft article on User Rights Assignment provides a detailed explanation of each of the user rights that can be set in Windows. Not every right listed here is critical from a security standpoint for penetration testers or defenders, but some rights granted to an account can lead to unintended consequences, such as privilege escalation or access to sensitive files. For example, if an attacker gains write access over a Group Policy Object (GPO) applied to an Organizational Unit (OU) containing one or more users they control, they could potentially leverage a tool like SharpGPOAbuse to assign targeted rights to a user. This would enable the attacker to perform many actions in the domain to further their access with these new rights.

| **Privilege** | **Description** |
| --- | --- |
| **SeRemoteInteractiveLogonRight** | This privilege could give our target user the right to log onto a host via Remote Desktop (RDP), which could potentially be used to obtain sensitive data or escalate privileges. |
| **SeBackupPrivilege** | This grants a user the ability to create system backups and could be used to obtain copies of sensitive system files that can be used to retrieve passwords such as the SAM and SYSTEM Registry hives and the NTDS.dit Active Directory database file. |
| **SeDebugPrivilege** | This allows a user to debug and adjust the memory of a process. With this privilege, attackers could utilize a tool such as Mimikatz to read the memory space of the Local System Authority (LSASS) process and obtain any credentials stored in memory. |
| **SeImpersonatePrivilege** | This privilege allows us to impersonate a token of a privileged account such as NT AUTHORITY\SYSTEM. This could be leveraged with a tool such as JuicyPotato, RogueWinRM, PrintSpoofer, etc., to escalate privileges on a target system. |
| **SeLoadDriverPrivilege** | A user with this privilege can load and unload device drivers that could potentially be used to escalate privileges or compromise a system. |
| **SeTakeOwnershipPrivilege** | This allows a process to take ownership of an object. At its most basic level, we could use this privilege to gain access to a file share or a file on a share that was otherwise not accessible to us. |

---

## Security in Active Directory

1. **CIA Triad**:
    - AD leans towards **Availability** and **Confidentiality**, but balancing these with **Integrity** is essential to strengthen security.
2. **Microsoft Local Administrator Password Solution (LAPS)**:
    - Randomizes and rotates local administrator passwords on Windows hosts to reduce the risk of lateral movement. Useful when combined with other security practices.
3. **Audit Policy Settings (Logging and Monitoring)**:
    - Essential for detecting unexpected activities like unauthorized changes, account password modifications, or potential attacks such as password spraying or Kerberos attacks.
4. **Group Policy Security Settings**:
    - **Account Policies**: Controls password policies, lockout settings, and Kerberos-related configurations.
    - **Local Policies**: Controls user rights, security event audits, and specific security settings like restricting users from installing software.
    - **Software Restriction Policies**: Limit which software can run on hosts.
    - **Application Control Policies**: Using tools like AppLocker to block unauthorized applications (e.g., CMD, PowerShell).
    - **Advanced Audit Policies**: Provides detailed auditing for various system activities, including account logon/logoff, policy changes, and privilege usage.
5. **Update Management (SCCM/WSUS)**:
    - Use tools like **WSUS** and **SCCM** to automate patch management and ensure timely deployment of critical security updates across systems.
6. **Group Managed Service Accounts (gMSA)**:
    - Automates password management for non-interactive services and provides a secure method for managing credentials across multiple hosts.
7. **Security Groups**:
    - Use security groups to assign permissions to users, streamlining access control and minimizing individual management of user permissions.
8. **Account Separation**:
    - Administrators should have separate accounts for everyday tasks and administrative duties to mitigate risks of privilege escalation if their regular account is compromised.
9. **Password Complexity + Passphrases + 2FA**:
    - Enforce strong password policies, use passphrases, and implement **Multi-Factor Authentication (MFA)**, particularly for Remote Desktop access.
10. **Limiting Domain Admin Usage**:
    - Restrict **Domain Admin** accounts to Domain Controllers only to reduce exposure to compromise.
11. **Auditing Stale Users and Objects**:
    - Regularly audit Active Directory for unused accounts or objects and disable or remove them to avoid potential security risks.
12. **Auditing Permissions and Access**:
    - Periodically review and ensure that users have the appropriate level of access for their roles. Limit access to high-privileged groups like **Domain Admins**.
13. **Restricted Groups**:
    - Use **Group Policy** to enforce group membership policies, ensuring only necessary users are part of high-privilege groups (e.g., **Domain Admins**).
14. **Limiting Server Roles**:
    - Avoid installing unnecessary roles (like IIS) on Domain Controllers. This minimizes the attack surface and isolates potential risks.
15. **Controlling Local Admin and RDP Rights**:
    - Restrict who has local admin rights and Remote Desktop (RDP) access to reduce unauthorized access and mitigate the risk of privilege escalation.
    

These practices help ensure a defense-in-depth approach, securing Active Directory against common attack vectors and minimizing the risk of exploitation within the environment.

---

## AD Group Policy

Group Policy (GP) is a powerful Windows feature that helps administrators manage users, computers, operating systems, and applications in a domain context. It is also a crucial tool for enhancing security in a network. By leveraging GP, administrators can enforce settings on user and computer accounts, but attackers can also abuse GPOs to escalate privileges and compromise domains if misconfigurations or vulnerabilities exist.

**Key Concepts:**

1. **Group Policy Object (GPO)**: A collection of policy settings applied to user(s) or computer(s). They define security, software configurations, access control, and more. GPOs are assigned unique GUIDs and can be linked to domains, organizational units (OUs), and sites.
2. **Common GPO Examples**:
    - Enforcing password complexity (e.g., minimum length, mixed character types).
    - Disabling USB ports or blocking specific applications.
    - Enforcing audit policies and logging.
    - Deploying or blocking software.
    - Controlling Remote Desktop settings.
3. **Order of Precedence**:
    - **Local Group Policy**: Applies only to the local machine and is overwritten by higher-level GPOs.
    - **Site Policy**: Applied at the enterprise site level.
    - **Domain-wide Policy**: Applied across the entire domain (e.g., password policies).
    - **Organizational Unit (OU)**: Specific settings for users or computers in an OU.
    - **Nested OUs**: Settings for objects within sub-OUs.
    The GPOs are processed in this hierarchical order, with the most specific GPO (applied to a child OU) having the highest precedence.
4. **Enforcement and Block Inheritance**:
    - **Enforced GPO**: Ensures the settings in a GPO cannot be overridden by lower-level OUs. The **Default Domain Policy** is a common example of an enforced GPO.
    - **Block Inheritance**: Prevents higher-level GPOs from being applied to a specific OU, ensuring that only settings applied directly to the OU will be enforced.
5. **Group Policy Refresh**:
    - By default, GPOs are refreshed every 90 minutes, with a random offset of +/- 30 minutes for client machines. Domain controllers refresh every 5 minutes.
    - To manually update GPOs, use the command `gpupdate /force`.
6. **Security Risks**:
    - Attackers who gain control over a GPO can modify it to elevate privileges, install malware, or set up persistent access.
    - Using tools like BloodHound, attackers may identify GPO misconfigurations and abuse them for lateral movement and privilege escalation.
7. **GPO Management**:
    - GPOs can be managed via the **Group Policy Management Console** (GPMC), PowerShell, or third-party applications.
    - The **Default Domain Policy** and **Default Domain Controllers Policy** are typically used to manage essential domain-wide security settings.

**GPO Hierarchy and Precedence**:

- **Link Order**: The order in which GPOs are applied to an OU. The GPO with the lowest link order has the highest precedence.
- **Enforced GPOs**: These override other GPOs, even at lower levels in the hierarchy.
- **Domain Policy and Default Settings**: The Default Domain Policy often contains global settings like password complexity. It holds the highest precedence unless explicitly overridden.

**GPO Security Considerations**:

- **Misconfigurations**: GPOs can introduce security flaws. For example, improper permissions on a GPO might allow attackers to modify settings and gain elevated privileges.
- **Persistence**: If attackers modify a GPO, they can establish persistence in a network by controlling critical systems, such as domain controllers.