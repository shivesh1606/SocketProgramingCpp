# 🧭 C++ DNS Resolver (WinSock + Raw DNS Client)
A modern educational DNS resolver written in C++ for Windows.

## ✨ Core Features
- ✔ OS-level resolution (`getaddrinfo`)
- ✔ Reverse DNS (IP → Domain)
- ✔ Raw DNS queries (UDP packets)
- ✔ A/AAAA/CNAME/MX (more coming soon)
- ✔ Custom DNS server selection (1.1.1.1 / 8.8.8.8 / local resolver)

## 📚 Table of Contents
- [Core Features](#-core-features)
- [Usage](#-usage)
- [Detailed Features](#-detailed-features)
- [How it Works](#-how-it-works)
- [Build Instructions](#-build-instructions)
- [Supported DNS Record Types](#-supported-dns-record-types)
- [Future Roadmap](#-future-roadmap)
- [Educational Value](#-educational-value)
- [Key Project Milestones](#-key-project-milestones)
- [Author](#-author)

---

## 📂 Usage

### 🔹 Basic Lookup
Uses the standard OS-level `getaddrinfo` function.
```bash
resolver google.com
```
```bash
Output:
IPv4: 142.250.193.46
Socket: Stream (TCP)
Protocol: TCP
CNAME: google.com
```

🔹 Reverse DNS Lookup
Converts an IP address back to its associated hostname (PTR record).
```bash
resolver --reverse 8.8.8.8
```
```bash
Output:
Reverse lookup for 8.8.8.8 -> dns.google
```
🔹 Raw DNS Query
Sends a manually constructed DNS packet over UDP to a specific server.
```bash
./resolver.exe --raw www.google.com 1.1.1.1 
```
```bash
Output Example:
Raw DNS query for: www.iitkgp.ac.in via 1.1.1.1
A: 203.110.240.87
CNAME: www.iitkgp.ac.in
```

## 📌 Detailed Features
1. Hostname → IP Resolver (getaddrinfo)
IPv4 + IPv6 support

Shows socket type (TCP/UDP/RAW)

Shows protocol (TCP/UDP/ICMP)

Supports fetching OS-provided canonical name (AI_CANONNAME)

2. Reverse Lookup (PTR)
Converts IP → domain using getnameinfo()

Supports both IPv4 & IPv6

Graceful fallback if PTR record does not exist

3. Raw DNS Query Engine
You manually build DNS packets:

Create DNS header

Encode QNAME

Send UDP packet

Receive DNS response

Parse ALL answers, including compressed names (0xC0xx)

Supports:

A (IPv4)

AAAA (IPv6)

CNAME

MX (Mail Exchange)

4. Select Your Own DNS Server
Use an optional argument to specify a resolver:

```bash
resolver --raw google.com 1.1.1.1
resolver --raw github.com 8.8.8.8
```

Useful for debugging, bypassing ISP cache, or comparing resolvers.

## 🧠 How it Works
How DNS Works (Simplified)
DNS is a global phonebook.

Forward Lookup: You know the name → want the number

Example: google.com → 142.250.193.46

Reverse Lookup: You know the number → want the name

Example: 8.8.8.8 → dns.google

(Only works if the owner created a PTR record)

⚙ How getaddrinfo() Works Internally
When you call getaddrinfo("google.com", NULL, &hints, &result);, this does not contact Google directly. Instead, the flow is:

```bash
Your Program
    ↓
Windows DNS Resolver
    ↓
Router DNS (e.g., 192.168.29.1)
    ↓
ISP / Public DNS (1.1.1.1 / 8.8.8.8)
    ↓
Authoritative Google DNS
    ↓
Returns A / AAAA / CNAME
```

This is why resolver --raw google.com 1.1.1.1 is a useful debugging tool.

🏷 Understanding CNAME
CNAME = Canonical Name = a domain alias.

Example: www.microsoft.com → www.microsoft.com-cdn.azureedge.net

Benefits:

Load balancing

CDN routing

Easy backend migration

“www” aliasing

💡 DNS Rule: A root domain (example.com) cannot have a CNAME record; it must have an A or AAAA record.

📬 What is an MX Record?
MX = Mail Exchange = an email routing record.

Example: gmail.com

10 alt1.aspmx.l.google.com

20 alt2.aspmx.l.google.com

It includes:

Priority (lower number = more preferred)

Mail server hostname

What is NS Record?
NS = Name Server Record
⭐ 1. NS Record (Name Server Record)

An NS record tells the world which DNS server is responsible for a domain.

Example for facebook.com:

a.ns.facebook.com
b.ns.facebook.com
c.ns.facebook.com
d.ns.facebook.com


These servers contain the real, original DNS data (A records, MX, TXT, etc).

➡️ NS = “These are the official servers for this domain.”
## 🛠 Build Instructions
Requires Windows (MinGW) and linking two key libraries.

⭐ 2. Authoritative vs Non-authoritative DNS
✅ Authoritative DNS

Comes directly from the domain’s official name servers (listed in NS records)

Contains the real truth about the domain

No caching — answers are generated from the zone file

Example:

nslookup facebook.com a.ns.facebook.com


This is authoritative because you asked the official server.

⚠️ Non-authoritative DNS

Comes from your ISP resolver, Google DNS, Cloudflare DNS, etc.

That resolver cached the answer earlier.

Faster, but not guaranteed to be the newest.

Example:

nslookup facebook.com


Here your ISP's DNS server is replying → non-authoritative.

➡️ Non-authoritative = cached
➡️ Authoritative = original source

```bash
g++ resolver.cpp -o resolver.exe -lws2_32 -ldnsapi
```

Libraries Required:

ws2_32.lib: WinSock networking (sockets, UDP, TCP).

dnsapi.lib: Windows DNS API (used for specific queries like MX, NS, TXT).

## 🧪 Supported DNS Record Types
Record,Meaning,Supported?
A,IPv4,✔
AAAA,IPv6,✔
CNAME,Canonical Name,✔
MX,Mail Exchange,✔
PTR,Reverse DNS,✔ (via getnameinfo)
NS,Name Server,🔜 Coming
TXT,"Domain Text (SPF, DKIM)",🔜 Coming
SOA,Start of Authority,🔜 Coming


## 🚀 Future Roadmap
🔹 Phase 1 (Next)
NS records

TXT (SPF/DKIM)

SOA

Human-readable flags (AA, RD, RA, TC)

🔹 Phase 2
--json output mode

--trace (to mimic dig +trace)

Colored terminal output

🔹 Phase 3 (Advanced)
DNSSEC awareness

TCP fallback (for large responses)

🔹 Phase 4 (Expert)
Build a local DNS server:

Forward queries

Cache responses

Support A/AAAA/CNAME locally

## 📚 Educational Value
This project is an excellent tool for learning:

Real packet encoding/decoding

DNS protocol internals

WinSock networking

UDP sockets

Recursive resolution

CNAME chains

MX parsing

String compression in protocols

It is highly recommended for:

Network Engineers

SRE/DevOps

Backend Developers

Low-level C++ Programmers

Cybersecurity Students

## 📜 Key Project Milestones
1. MX Records Added

commit 2ca32c9cf6e30c8ad455e8f94bdd252b5f52e839 MX parsing, preference extraction.

2. CNAME Resolution (Raw)

commit b79089f82601c89d23dee39ae0fb4a7ac125bee6 Recursive CNAME following.

3. Socket Type + Protocol Detection

commit 95feebed49cd7f5a4755257d5a42d932451fc9a5 Displays TCP/UDP/ICMP info for each returned IP.

4. Reverse Lookup + Full Resolver

commit 81964b8f7a68a64eb89246b6d2899485a787c70f Supports PTR via getnameinfo.

## 🧑‍💻 Author
Shivesh Chaturvedi

B.Tech, IIT Kharagpur

SRE + Software Developer

GitHub: shivesh1606