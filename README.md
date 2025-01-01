Awesome-Thick-Client-Security [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
===================
A curated list of Thick Client Security Resource (Blogs, Course, Video Playlist and Vulnerable Applications to practise on) for thick client penetration testing.

Inspired by [awesome projects](https://github.com/sindresorhus/awesome).

Table of Contents
=================

- [Thick Client Testing Methodology](#thick-client-testing-methodology)
  - [Information Gathering](#Information-Gathering)
2. [Thick Client Testing Tools](#thick-client-testing-tools)


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

Thick Client Testing Tools
==========================

## Information Gathering
### Static Tools
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

### .NET Decompilers And De-obfuscators Tools: (Used in Binary Analysis)
- dnSpy - A .NET debugger and assembly editor.
  - OS: Windows
  - License: Free
- ILSpy* - ILSpy is the open-source .NET assembly browser and decompiler.
- JetBrains DotPeek - A program for determining types of files for Windows, Linux, and macOS.
- de4dot* - .NET deobfuscator and unpacker.



