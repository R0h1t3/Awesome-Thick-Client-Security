Awesome-Thick-Client-Security [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
===================
A curated list of Thick Client Security Resource (Blogs, Course, Video Playlist and Vulnerable Applications to practise on) for thick client penetration testing.

Inspired by [awesome projects](https://github.com/sindresorhus/awesome).

Table of Contents
=================

- [Thick Client Testing Methodology](#thick-client-testing-methodology)
  - [Information Gathering](#Information-Gathering)
  - [Client Side Attacks](#Client-Side-Attacks)
  - [Network Side Attacks](#Network-Side-Attacks)
  - [Server Side Attacks](#Server-Side-Attacks)
    
- [Thick Client Testing Tools](#thick-client-testing-tools)
  - [Information Gathering](#Information-Gathering)
    - [Static Tools](#Static-Tools)
    - [.NET Decompilers And De-obfuscators Tools](#.NET-Decompilers-And-De-obfuscators-Tools)
    - [Network Sniffers](#Network-Sniffers)
  - [Client Side Attacks](#Client-Side-Attacks)
    - [File Analysis Tools, Sensitive Data Storage On Files And Registry](#File-Analysis-Tools,-Sensitive-Data-Storage-On-Files-And-Registry)
    - [Binary Analysis Tools](#Binary-Analysis-Tools)
    - [Memory Analysis Tools](#Memory-Analysis-Tools)
    - [DLL Hijacking](#DLL-Hijacking)
    - [Weak GUI Control Tools](#Weak-GUI-Control-Tools)
  - [Network-Side Attacks](#Network--Side-Attacks)
    - [Proxy Tools](#Proxy-Tools)
  - [Server-Side Attacks](#Server--Side-Attacks)
    - [Miscellaneous](#Miscellaneous)
   
- [References](#References)


------

## Thick Client Testing Methodology
### Information Gathering
- Application Architecture
  - Business Logic
- Platform Mapping
  - Understanding Application and Infrastructure
- Languages & Framework
  - Common Low level Vulnerabilities and CVEs
- Behaviour Analysis
  - Identify Network Communication
  - Observe Application Processes
  - Functionality Testing
  - Identify all entry points
  - Analyze Security Mechanism (Authentication & Authorization)

### Client Side Attacks
- File Analysis
  - Information Disclosure
- Binary Analysis
  - Static Analysis (De-compilation)
  - Dynamic Analysis (Run-Time Reverse Engineering)
- Memory Analysis
  - Sensitive Information storage in Memory
  - Memory Manipulation
  - Registry Analysis
  - Assembly Analysis
- GUI Manipulation
  - Display hidden Objects
  - Activate Disable Functionalities
  - Privilege Escalation
- DLL Hijacking 

### Network Side Attacks
- Network Traffics
  - Sensitive Installation Information
  - Installation/Uninstalltion/Update/Run Time Traffic
  - Data Disclosure
  - Vulnerable API

### Server Side Attacks
- Network Layer Attacks (TCP-UDP Attacks)
- Possible OWASP 10 Attacks types
- Miscellaneous Attacks - WCF Scan

------

## Thick Client Testing Tools
### Information Gathering
#### Static Tools
- [CFF Explorer](https://ntcore.com/?page_id=388) - A tool that was designed to make PE editing as easy as possible without losing sight of the portable executable’s internal structure.
  - Info about the exe files
  - DLLs used in the exe
  - Hex editing can be done for the file
  - After the changes are made the exe can be rebuilt and used
- [Exeinfo PE](http://www.exeinfo.byethost18.com/?i=1) - A tool that detects most common packers, cryptors and compilers for PE files.
  - Can conduct many many scans and has many integrated checkers
-  [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) - A program for determining file types for Windows, Linux and macOS and get signatures along with performing scan and reviews
- [Cutter](https://cutter.re/) - A tool that scans any files you pass it for UNICODE or ASCII strings of a default length of three or more UNICODE or ASCII characters.
  - Retrieves all the strings in the exe file

#### .NET Decompilers And De-obfuscators Tools: (Used in Binary Analysis)
- [dnSpy](https://github.com/0xd4d/dnSpy) - A .NET debugger and assembly editor.
  - OS: Windows
  - License: Free
- [ILSpy](https://github.com/icsharpcode/ILSpy)8 - ILSpy is the open-source .NET assembly browser and decompiler.
- [JetBrains DotPeek](https://www.jetbrains.com/decompiler/) - A program for determining types of files for Windows, Linux, and macOS.
- [de4dot](https://github.com/0xd4d/de4dot)* - .NET deobfuscator and unpacker.

#### Network Sniffers
- [Wireshark](https://www.wireshark.org/download.html) - Wireshark is the world’s foremost and most widely-used network protocol analyzer.
  - Note: This is need only for 3-tier thick client and not 2-tier thick client
  - Can see the packets that are getting transferred
- [TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview)* - TCPView is a Windows program that shows detailed listings of all TCP and UDP endpoints on your system, including the local and remote addresses and the state of TCP connections.
  - Only able to see if there is a connection happening and the IP address
- [Microsoft Network Monitor 3.4](https://www.microsoft.com/en-us/download/details.aspx?id=4865) - Microsoft Network Monitor 3.4 is a tool for network traffic capture and protocol analysis.
- [MITM relay](https://github.com/jrmdev/mitm_relay) - a type of tool that allows an attacker to intercept and modify non-HTTP protocols through existing traffic interception software such as Burp Proxy or Proxenet. It can be particularly useful for thick clients' security assessments.

### Client Side Attacks
#### File Analysis Tools, Sensitive Data Storage On Files And Registry
- [Sysinternals Utilities](https://docs.microsoft.com/en-us/sysinternals/downloads/) - (Process Monitor, Regedit, Regshot, AccessEnum) [GitHub](https://github.com/MicrosoftDocs/sysinternals/blob/live/sysinternals/downloads/index.md)
  - OS: Windows
  - License: Free
  - [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) - An advanced monitoring tool for Windows that shows real-time file system, Registry and process/thread activity.
    - Shows all the information of the running processes from size to memory accessed
  - [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) - Provides the functionality of the Windows Task Manager along with a rich set of features for collecting information about processes running on the user’s system. It can be used as the first step in debugging software.
    - Shows the performance of the process and other informations related to it
  - [Strings](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)
- [Process Hacker](https://processhacker.sourceforge.io/) - A free, powerful multi-purpose tool that helps you monitor system resources, debug software and detect malware.
- [Regshot](https://sourceforge.net/projects/regshot/) - An open-source (LGPL) registry compare utility that allows you to quickly take a snapshot of your registry and then compares it with a second one used after doing system changes or installing a new software product.

#### Binary Analysis Tools
- [Ghidra](https://www.ghidra-sre.org/) - A suite of free software reverse engineering tools developed by the NSA’s Research Directorate. It was originally exposed in WikiLeaks’s “Vault 7” publication and is now maintained as open-source software.
- [Immunity Debugger](https://immunityinc.com/products/debugger/) - Immunity Debugger is a powerful new way to write exploits, analyze malware and reverse engineer binary files.
- [Interactive Disassembler (IDA Pro)](https://www.hex-rays.com/products/ida/) - Proprietary multi-processor disassembler and debugger for Windows, GNU/Linux or macOS - Free
- [OllyDbg](http://www.ollydbg.de/) - x86 debugger for Windows binaries that emphasizes binary code analysis.
  - Note: Only for 32 bit executable files
- [x64dbg](http://x64dbg.com/) - Open source x64/x32 debugger for windows.
  - Note: Use Checksec plugin to find more direct vulnerabilities
- [JD-GUI](https://github.com/java-decompiler/jd-gui) - A standalone Java decompiler GUI.
- [Jadx](https://github.com/skylot/jadx) - Dex to Java decompiler.
- [Bytecode Viewer](https://github.com/Konloch/bytecode-viewer) - A lightweight user-friendly Java bytecode viewer.
- [UPX Decompression](https://upx.github.io/) - A free, portable, extendable, high-performance executable packer for several executable formats.
- [Frida](https://frida.re/) - A dynamic instrumentation toolkit for developers, reverse-engineers and security researchers.
- [Binary Ninja](https://binary.ninja/) - Binary Ninja is an interactive decompiler, disassembler, debugger, and binary analysis platform built by reverse engineers, for reverse engineers. Developed with a focus on delivering a high-quality API for automation and a clean and usable GUI, Binary Ninja is in active use by malware analysts, vulnerability researchers, and software developers worldwide. - Paid 

#### Memory Analysis Tools
- [Winhex](https://www.x-ways.net/winhex/index-m.html) - An advanced monitoring tool for Windows that shows real-time file system, Registry and process/thread activity.
- [Volatility](https://github.com/volatilityfoundation/volatility) - An open-source (LGPL) registry compare utility that allows you to quickly take a snapshot of your registry and then compares it with a second one – used after doing system changes or installing a new software product.
- [Userdump](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/use-userdump-create-dump-file) - A command-line utility tool used to generate a user dump of a process that shuts down with an exception or that stops responding. 
- [HxD](https://mh-nexus.de/en/hxd/) - A hex editor that allows users to edit binary files, disks, and disk images. It is used for data recovery, forensics, and reverse engineering
- [Accessenum](https://learn.microsoft.com/en-us/sysinternals/downloads/accessenum) - A tool that shows the user and group permissions on files, directories, and registry keys. It is used to identify potential security vulnerabilities by showing which users and groups have access to sensitive files and directories
- [Win-AFL](https://github.com/mboehme/winaflfast) - a popular fuzzing tool for coverage-guided fuzzing
- [AFL++](https://github.com/AFLplusplus/AFLplusplus) - a community-maintained fork of AFL that includes new features and speedups, and is considered a superior fork to Google's AFL with more speed, more and better mutations, more and better instrumentation, and custom module support.
- [Sulley](https://github.com/OpenRCE/sulley) - fuzz testing framework that is used for automated software testing.

#### DLL Hijacking
- [DLLSpy](https://github.com/cyberark/DLLSpy) - A tool that detects DLL hijacking in running processes and services and in their binaries.
- [Robber](https://github.com/MojtabaTajik/Robber) - An open-source tool for finding executables prone to DLL hijacking.
- [Impulsivedll Hijacker](https://github.com/knight0x07/ImpulsiveDLLHijack) - C# based tool which automates the process of discovering and exploiting DLL Hijacks in target binaries.

#### Weak GUI Control Tools
- [WinSpy++](https://www.softpedia.com/get/Programming/Other-Programming-Files/WinSpyPlusPlus.shtml) - A tool whose purpose is to help you view and modify the properties of any window in your system with great ease.
- [WinManipulate](https://github.com/appsecco/winmanipulate) - A simple tool to manipulate window objects in Windows.
- [Windows Enabler](https://windows-enabler.en.uptodown.com/windows) - A simple tool that lets you activate functions your thick client application has blocked.
- [UISpy](https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/march/test-run-automating-ui-tests-in-wpf-applications) - A GUI utility tool that allows users to examine properties of the UI components of a WPF application. UISpy is part of the Microsoft Windows SDK and is available as a free download from Microsoft.com/downloads.
- [Window Detective](https://github.com/WindowDetective/WindowDetective) - A tool that allows users to view and manipulate window properties. It is used to identify the properties of windows, such as their size, position, and class name. Window Detective is useful for debugging and testing applications.

### Network-Side Attacks
#### Proxy Tools
- [Burp Suite](https://portswigger.net/burp) - Burp Suite Professional is an advanced set of tools for testing web security.
  - OS: Windows, Mac and Linux
  - License: Free, Paid
- [Fiddler](https://www.telerik.com/fiddler) - Fiddler is a free web debugging tool which logs all HTTP(S) traffic between your computer and the Internet.
  - License  - Paid or Free
- [Echo Mirage](https://sourceforge.net/projects/echomirage.oldbutgold.p/) - Echo Mirage is a versatile local proxy tool that can be used to intercept and modify TCP payloads for local Windows applications.
  - OS: Windows
  - License: Free
- [Charles Web Debugging Proxy](https://www.charlesproxy.com/) - Charles is an HTTP proxy that enables to view all of the HTTP and SSL / HTTPS traffic between the local machine and the Internet. This includes requests, responses and the HTTP headers.
- [Javascoop](https://github.com/CodeMason/JavaSnoop)(Must) - For Java thick clients, this allows for interception proxy of any method in the JVM
  - OS: Windows, Mac and Linux
  - License: Free
 
### Server-Side Attacks
#### Miscellaneous
- [Metasploit](https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers) - used for side loading/ DLL and Exe injection
- [Binscope](https://www.microsoft.com/en-us/download/details.aspx?id=44995) - a binary analyzer tool developed by Microsoft that analyzes binaries on a project-wide level to ensure that they have been built in compliance with Microsoft's security recommendations
- [Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) - a command-line utility developed by Sysinternals, which is now a part of Microsoft, that shows file version number, timestamp information, and digital signature details, including certificate chains
- [Visual Code Grepper](https://sourceforge.net/projects/visualcodegrepp/)  - VCG is an automated code security review tool for C++, C#, VB, PHP, Java, PL/SQL and COBOL, which is intended to speed up the code review process by identifying bad/insecure code.
- [Attack Surface Analyzer (ASA)](https://en.wikipedia.org/wiki/Attack_Surface_Analyzer) - a security tool developed by Microsoft that analyzes the attack surface of a Windows, Linux, or MacOS system and reports on potential security vulnerabilities
- [WcfScan](https://github.com/malcomvetter/WcfScan) - a tool that can be used to scan NET.TCP WCF endpoints to test the security of their binding configurations
- [AppSec Labs WCF Toolkit](https://sourceforge.net/projects/appsec-labs-wcf-toolkit/) - provides a generic client and a proxy that can be used to test and manipulate traffic between the client and the server.
- [SQLMap](https://github.com/sqlmapproject/sqlmap) - Tool used to test for SQL injection
- [Stunnel](https://www.stunnel.org/) - open-source multi-platform application that is used to provide a universal TLS/SSL tunneling service.


------


## References
- [Thick Client Penetration Testing Methodology](https://www.cyberark.com/resources/threat-research-blog/thick-client-penetration-testing-methodology)
- [Thick_Client_Pentesting_The-HackersMeetup_PDF](https://github.com/hexachordanu/Thick-Client-Pentesting)
- [Introduction to Thick Client PenetrationTesting](https://studylib.net/doc/25753166/blog-securelayer7-net-thick-client-penetration-testing-1-)
- [Thick Client Userful Link's](https://github.com/RakeshKengale/RaKKeN/blob/master/Index/Thick_Client.md)
- [Vulnerable Client-Server Application (VuCSA)](https://github.com/Warxim/vucsa)
- [Thick Client Pentest: Modern Approaches and Techniques](https://infosecwriteups.com/thick-client-pentest-modern-approaches-and-techniques-part-1-7bb0f5f28e8e)
- [Medium Articles on Thick Client Security](https://medium.com/tag/thick-client-security)
- [Thick Client Penetration Testing: Uncovering Vulnerabilities in Desktop Applications](https://www.darkrelay.com/post/thick-client-penetration-testing)
- [NetAPI - Introduction to Hacking Thick Clients](https://www.netspi.com/blog/technical-blog/thick-application-penetration-testing/introduction-to-hacking-thick-clients-part-1-the-gui/)
- [Abhi Gowda - Medium Articles on Thick Client Security](https://abhigowdaa.medium.com/)
- [Thick client penetration testing series](https://medium.com/@Dinesh_infosec/thick-client-penetration-testing-series-87214a42a1e7)
- [Thick client applications](https://www.happiestminds.com/whitepapers/Thick-client-application.pdf)
- [Thick Client Penetration Testing.pdf](https://www.slideshare.net/slideshow/thick-client-penetration-testingpdf/252723700)
- [Pentesting Java Thick Applications with Burp JDSer](https://www.netspi.com/blog/technical-blog/thick-application-penetration-testing/pentesting-java-thick-applications-with-burp-jdser/)
- [Payatu - Thick Client Pentesting](https://payatu.com/blog/thick-client-penetration-testing/)
- [Threat Intelligence - Thick Client Application Penetration Test](https://www.threatintelligence.com/blog/thick-client-application-penetration-test)
- [Practical thick client application penetration testing using damn vulnerable thick client app](https://infosecinstitute.com/resources/penetration-testing/practical-thick-client-application-penetration-testing-using-damn-vulnerable-thick-client-app-part-1/)
- [Thick Client Penetration Testing on DVTA](https://www.hackingarticles.in/thick-client-penetration-testing-on-dvta/)
- [OWASP - Thick Client Application Security](https://www.scribd.com/document/57734261/Thick-Client-Application-Security#)
- [Cobalt.io - Attacking Windows Applications](https://www.cobalt.io/blog/attacking-windows-applications-part-1)
- [Christofer Simbar - Medium Articles](https://medium.com/@christoferdirk/list/thick-client-security-e2f828e8f134)
- [Varutra - Thick Client Penetration Testing](https://www.varutra.com/category/thick-client-penetration-testing/)
- [Mohit Maurya - Medium Articles](https://iammohitmaurya.medium.com/)
- [Github - Terrible Thick Client](https://github.com/kartikdurg/Terrible-Thick-Client)
- [Breaking Bad: Tearing apart a thick client app to steal data](https://blog.appsecco.com/breaking-bad-tearing-apart-a-thick-client-app-to-steal-data-7e44f8698b2a)
- [Thick Client Security Testing - Short Tutorial](https://allabouttesting.org/thick-client-security-testing-short-tutorial/)
- [SVJA - Super Vulnerable Java Application](https://github.com/theronielanddaronpodcastshow/svja)
- [The art of Fuzzing](https://bushido-sec.com/index.php/2023/06/19/the-art-of-fuzzing/)
