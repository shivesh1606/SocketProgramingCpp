#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <cstring>
#include <windns.h>

#pragma comment(lib, "dnsapi.lib")

#pragma comment(lib, "ws2_32.lib")

using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::vector;
using std::map;

/* ---------- Utility helpers ---------- */
std::string familyToStr(int family) {
    if (family == AF_INET) return "IPv4";
    if (family == AF_INET6) return "IPv6";
    return "Unknown";
}

std::string sockTypeToStr(int type) {
    if (type == SOCK_STREAM) return "Stream (TCP)";
    if (type == SOCK_DGRAM) return "Datagram (UDP)";
    if (type == SOCK_RAW) return "Raw Socket";
    return "Other";
}

std::string protocolToStr(int proto) {
    if (proto == IPPROTO_TCP) return "TCP";
    if (proto == IPPROTO_UDP) return "UDP";
    if (proto == IPPROTO_ICMP) return "ICMP";
    if (proto == IPPROTO_ICMPV6) return "ICMPv6";
    return "Other";
}

void print_usage() {
    cout << "Usage:\n";
    cout << "  resolver <hostname>\n";
    cout << "  resolver --reverse <ip>\n";
    cout << "  resolver --raw <hostname> [dns-server]\n";
    cout << "\nExamples:\n";
    cout << "  resolver google.com\n";
    cout << "  resolver --reverse 8.8.8.8\n";
    cout << "  resolver --raw google.com 1.1.1.1\n";
}

/* ---------- Reverse lookup ---------- */
void do_reverse_lookup(const std::string& ip_address) {

    sockaddr_in sa{};
    int ss_len=0;
    memset(&sa, 0, sizeof(sa));
    in_addr ipv4addr;
    if(inet_pton(AF_INET, ip_address.c_str(), &ipv4addr) == 1) {
        sockaddr_in *sa4 = (sockaddr_in *)&sa;
        sa4->sin_family = AF_INET;
        sa4->sin_addr = ipv4addr;
        ss_len = sizeof(sockaddr_in);
    }
    else{
        in6_addr ipv6addr;
        if(inet_pton(AF_INET6,ip_address.c_str(),&ipv6addr) == 1){
            sockaddr_in6 *sa6 = (sockaddr_in6 *)&sa;
            sa6->sin6_family = AF_INET6;
            sa6->sin6_addr = ipv6addr;
            ss_len = sizeof(sockaddr_in6);
        }
        else{
            cerr << "Error: '" << ip_address << "' is not a valid IPv4 or IPv6 address.\n";
            return;
        }
    }
    char host[NI_MAXHOST]={0};

    // NI_NAMEREQD would fail if no PTR record; we'll try without flags first
    int flags = 0; // or NI_NAMEREQD to force failure if no name
    int ret = getnameinfo((sockaddr*)&sa, ss_len, host, sizeof(host), NULL, 0, flags);
    if (ret != 0) {
        cerr << "getnameinfo failed: " << gai_strerrorA(ret) << "\n";
        return;
    }

    cout << "Reverse lookup for " << ip_address << " -> " << host << "\n";

}


/* ---------- Raw DNS client: packet building & parsing ---------- */

/* DNS header structure (12 bytes) */
#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

/* Helper: write 16-bit/32-bit in network byte order */
void write_u16(vector<uint8_t>& buf, uint16_t v) {
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back(v & 0xFF);
}
void write_u32(vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((v >> 24) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back(v & 0xFF);
}

/* Build a simple DNS query for type A (1) or AAAA (28) or ANY (255).
   We'll query type 255 (ANY) to get A/AAAA/CNAME in one shot. */
vector<uint8_t> build_dns_query(const string& name, uint16_t qtype, uint16_t id) {
    vector<uint8_t> out;
    DNSHeader hdr;
    hdr.id = htons(id);
    hdr.flags = htons(0x0100); // recursion desired
    hdr.qdcount = htons(1);
    hdr.ancount = 0;
    hdr.nscount = 0;
    hdr.arcount = 0;

    // header
    out.resize(sizeof(DNSHeader));
    memcpy(out.data(), &hdr, sizeof(DNSHeader));

    // question: name in label format
    size_t start = out.size();
    size_t pos = 0;
    while (pos < name.size()) {
        size_t dot = name.find('.', pos);
        if (dot == string::npos) dot = name.size();
        size_t len = dot - pos;
        out.push_back((uint8_t)len);
        for (size_t i = 0; i < len; ++i) out.push_back(name[pos + i]);
        pos = dot + 1;
    }
    out.push_back(0x00); // null label terminator

    // qtype & qclass (IN)
    write_u16(out, qtype);
    write_u16(out, 1); // class IN

    return out;
}

/* Name decoding with compression support.
   buffer: pointer to DNS message
   bufsize: total size
   offset: current offset (will be advanced for non-pointer reads)
   returns: decoded name, and optionally advances local_offset (but not in pointer cases)
*/
string decode_name(const uint8_t* buffer, size_t bufsize, size_t& offset) {
    string name;
    bool jumped = false;
    size_t orig_offset = offset;
    size_t jumps = 0;
    while (offset < bufsize) {
        uint8_t len = buffer[offset];
        if (len == 0) {
            if (!jumped) offset += 1;
            break;
        }

        // pointer? top two bits 11
        if ((len & 0xC0) == 0xC0) {
            if (offset + 1 >= bufsize) return "";
            uint8_t b2 = buffer[offset + 1];
            uint16_t pointer = ((len & 0x3F) << 8) | b2;
            if (!jumped) orig_offset = offset + 2;
            offset = pointer;
            jumped = true;
            if (++jumps > 10) return ""; // avoid loops
            continue;
        } else {
            // normal label
            offset++;
            if (offset + len > bufsize) return "";
            if (!name.empty()) name += '.';
            for (int i = 0; i < len; ++i) {
                name.push_back((char)buffer[offset + i]);
            }
            offset += len;
        }
    }

    if (jumped) {
        // if we jumped, return the original advancement
        offset = orig_offset;
    }
    return name;
}

/* Parse answers: supports A, AAAA, CNAME */
struct DNSAnswer {
    string name;
    uint16_t type;
    uint32_t ttl;
    string data_str; // ip for A/AAAA or target for CNAME
};

bool parse_dns_response(const vector<uint8_t>& resp, vector<DNSAnswer>& answers, vector<string>& cnames) {
    if (resp.size() < sizeof(DNSHeader)) return false;
    const uint8_t* buf = resp.data();
    size_t bufsize = resp.size();

    // header
    uint16_t id = (buf[0] << 8) | buf[1];
    uint16_t flags = (buf[2] << 8) | buf[3];
    uint16_t qdcount = (buf[4] << 8) | buf[5];
    uint16_t ancount = (buf[6] << 8) | buf[7];
    // skip nscount and arcount for now

    size_t offset = sizeof(DNSHeader);

    // skip question section (qdcount times)
    for (int i = 0; i < qdcount; ++i) {
        string qname = decode_name(buf, bufsize, offset);
        if (offset + 4 > bufsize) return false;
        uint16_t qtype = (buf[offset] << 8) | buf[offset+1];
        uint16_t qclass = (buf[offset+2] << 8) | buf[offset+3];
        offset += 4;
    }

    // parse answers
    for (int i = 0; i < ancount; ++i) {
        string name = decode_name(buf, bufsize, offset);
        if (offset + 10 > bufsize) return false;
        uint16_t type = (buf[offset] << 8) | buf[offset+1];
        uint16_t cls  = (buf[offset+2] << 8) | buf[offset+3];
        uint32_t ttl  = (buf[offset+4] << 24) | (buf[offset+5] << 16) | (buf[offset+6] << 8) | buf[offset+7];
        uint16_t rdlen = (buf[offset+8] << 8) | buf[offset+9];
        offset += 10;

        if (offset + rdlen > bufsize) return false;

        if (type == 1 && rdlen == 4) { // A
            char ipbuf[INET_ADDRSTRLEN];
            const uint8_t* a = buf + offset;
            sprintf_s(ipbuf, sizeof(ipbuf), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
            DNSAnswer ans;
            ans.name = name;
            ans.type = type;
            ans.ttl = ttl;
            ans.data_str = std::string(ipbuf);
            answers.push_back(ans);
        } else if (type == 28 && rdlen == 16) { // AAAA
            char ipbuf[INET6_ADDRSTRLEN];
            // inet_ntop not directly available for raw buffer easily, format manually using WSAAddressToString
            SOCKADDR_IN6 sa6;
            memset(&sa6, 0, sizeof(sa6));
            sa6.sin6_family = AF_INET6;
            memcpy(&sa6.sin6_addr, buf + offset, 16);
            DWORD iplen = INET6_ADDRSTRLEN;
            char outbuf[INET6_ADDRSTRLEN] = {0};
            // use WSAAddressToStringA
            SOCKADDR_STORAGE ss;
            memset(&ss, 0, sizeof(ss));
            ((SOCKADDR_IN6*)&ss)->sin6_family = AF_INET6;
            memcpy(&((SOCKADDR_IN6*)&ss)->sin6_addr, buf + offset, 16);
            WSAAddressToStringA((LPSOCKADDR)&ss, sizeof(SOCKADDR_IN6), NULL, outbuf, &iplen);
            DNSAnswer ans;
            ans.name = name;
            ans.type = type;
            ans.ttl = ttl;
            ans.data_str = std::string(outbuf);
            answers.push_back(ans);
        } else if (type == 5) { // CNAME
            size_t tmp_offset = offset;
            string cname = decode_name(buf, bufsize, tmp_offset);
            cnames.push_back(cname);
            DNSAnswer ans;
            ans.name = name;
            ans.type = type;
            ans.ttl = ttl;
            ans.data_str = cname;
            answers.push_back(ans);
        } 
        else if(type ==2){ // NS
            size_t tmp_offset = offset;
            string nsname = decode_name(buf, bufsize, tmp_offset);
            // we can store NS records if needed
            DNSAnswer ans;
            ans.name = name;
            ans.type = type;
            ans.ttl = ttl;
            ans.data_str = nsname;
            answers.push_back(ans);

        }
        else {
            // ignore other types
        }

        offset += rdlen;
    }

    return true;
}

/* Send a DNS query to server and get response (blocking, simple) */
bool send_dns_query_udp(const string& server_ip, const string& qname, vector<uint8_t>& out_resp, int qtype=255, int timeout_ms=2000) {
    // server_ip currently handled for IPv4 strings
    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(53);
    if (inet_pton(AF_INET, server_ip.c_str(), &serv.sin_addr) != 1) {
        cerr << "Invalid DNS server IP: " << server_ip << "\n";
        return false;
    }

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) {
        cerr << "socket() failed: " << WSAGetLastError() << "\n";
        return false;
    }

    // build query (id random)
    uint16_t id = (uint16_t)(rand() & 0xFFFF);
    vector<uint8_t> query = build_dns_query(qname, (uint16_t)qtype, id);

    // send
    int sent = sendto(s, (const char*)query.data(), (int)query.size(), 0, (sockaddr*)&serv, sizeof(serv));
    if (sent == SOCKET_ERROR) {
        cerr << "sendto() failed: " << WSAGetLastError() << "\n";
        closesocket(s);
        return false;
    }

    // set timeout
    DWORD tv = timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // receive (single read)
    out_resp.resize(4096);
    sockaddr_in from{};
    int fromlen = sizeof(from);
    int rec = recvfrom(s, (char*)out_resp.data(), (int)out_resp.size(), 0, (sockaddr*)&from, &fromlen);
    if (rec == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAETIMEDOUT) {
            cerr << "DNS query timed out\n";
        } else {
            cerr << "recvfrom() failed: " << e << "\n";
        }
        closesocket(s);
        return false;
    }
    out_resp.resize(rec);
    closesocket(s);
    return true;
}

/* High level: resolve name via raw DNS, follow CNAME chain (depth-limited) */
// Replace your current raw_resolve_follow with the following improved version.
// This queries A(1) then AAAA(28) separately (more reliable than ANY), and still follows CNAMEs.

bool raw_resolve_follow(const string& qname, const string& dns_server, vector<DNSAnswer>& final_answers, int depth=0) {
    if (depth > 6) {
        cerr << "CNAME chain too deep\n";
        return false;
    }

    // We'll try A then AAAA. If we get IPs for the current qname we return them.
    // But we must still capture any CNAMEs returned so we can follow them.
    const int qtypes[] = { 1, 28 }; // A, AAAA

    bool anySuccess = false;
    vector<string> collectedCnames;

    for (int qtype : qtypes) {
        vector<uint8_t> resp;
        if (!send_dns_query_udp(dns_server, qname, resp, qtype)) {
            // if timeout or error for this qtype, continue to next qtype
            continue;
        }

        // Uncomment to debug raw response bytes:
        // std::cerr << "DEBUG: raw response (" << resp.size() << " bytes): ";
        // for (auto b : resp) { char buf[4]; sprintf_s(buf, "%02X ", b); std::cerr << buf; }
        // std::cerr << "\n";

        vector<DNSAnswer> answers;
        vector<string> cnames;
        if (!parse_dns_response(resp, answers, cnames)) {
            // parsing failed for this response; try next qtype
            continue;
        }

        // collect A/AAAA answers for this qname (only include answers that match the queried name)
        for (auto &a : answers) {
            if ((a.type == 1 && qtype == 1) || (a.type == 28 && qtype == 28)) {
                // push only answers whose name equals qname (some responses may include other records)
                if (a.name == qname || a.name.empty()) {
                    final_answers.push_back(a);
                    anySuccess = true;
                } else {
                    // also accept if the name is a CNAME target that matches later logic
                    final_answers.push_back(a);
                    anySuccess = true;
                }
            }
            // also capture CNAME answers into final list so we can show chain
            if (a.type == 5) {
                final_answers.push_back(a);
                collectedCnames.push_back(a.data_str);
            }
        }

        // also collect any CNAME list returned by parse function
        for (auto &cn : cnames) collectedCnames.push_back(cn);

        // if we already found IPs, no need to try the other qtype for this name
        if (anySuccess) break;
    }

    // If we found IPs, include any CNAMEs discovered and return.
    if (anySuccess) {
        // ensure unique CNAMEs and answers already appended
        return true;
    }

    // No A/AAAA found for this qname. If we found CNAME(s), follow the first one.
    if (!collectedCnames.empty()) {
        string target = collectedCnames[0];
        // add a CNAME record entry for display
        DNSAnswer cnameAns;
        cnameAns.name = qname;
        cnameAns.type = 5;
        cnameAns.ttl = 0;
        cnameAns.data_str = target;
        final_answers.push_back(cnameAns);

        // follow target recursively
        return raw_resolve_follow(target, dns_server, final_answers, depth + 1);
    }

    // nothing found (no IPs, no CNAMEs)
    return true; // success but no answers
}



void resolve_mx(const std::string& domain) {
    PDNS_RECORD pRecord = nullptr;
    DNS_STATUS status;

    status = DnsQuery_A(
        domain.c_str(),
        DNS_TYPE_MX,
        DNS_QUERY_STANDARD,
        NULL,
        &pRecord,
        NULL
    );

    if (status != 0) {
        std::cerr << "MX lookup failed: " << status << "\n";
        return;
    }

    std::cout << "\n[MX Records for " << domain << "]\n";

    PDNS_RECORD p = pRecord;
    while (p) {
        if (p->wType == DNS_TYPE_MX) {
            std::cout << "Priority : " << p->Data.MX.wPreference << "\n";
            std::cout << "Mail Exchanger : " << p->Data.MX.pNameExchange << "\n";
            std::cout << "--------------------------\n";
        }
        p = p->pNext;
    }

    DnsRecordListFree(pRecord, DnsFreeRecordList);
}

void resolve_ns(const std::string& domain) {
    PDNS_RECORD pRecord = nullptr;
    DNS_STATUS status;

    status = DnsQuery_A(
        domain.c_str(),
        DNS_TYPE_NS,
        DNS_QUERY_STANDARD,
        NULL,
        &pRecord,
        NULL
    );

    if (status != 0) {
        std::cerr << "NS lookup failed: " << status << "\n";
        return;
    }

    std::cout << "[NS Records for " << domain << "]\n";

    PDNS_RECORD p = pRecord;
    while (p) {
        if (p->wType == DNS_TYPE_NS) {
            std::cout << "Nameserver : " << p->Data.NS.pNameHost << "\n";
            std::cout << "TTL        : " << p->dwTtl << "\n";
            std::cout << "-----------------------------\n";
        }
        p = p->pNext;
    }

    DnsRecordListFree(pRecord, DnsFreeRecordList);
}


int main(int argc, char* argv[]) {
      if (argc < 2) {
        print_usage();
        return 1;
    }

    // Initialize WinSock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        cerr << "WSAStartup failed\n";
        return 1;
    }

    string first = argv[1];

    if (first == "--reverse") {
        if (argc != 3) {
            cerr << "Error: --reverse requires an IP address argument\n";
            print_usage();
            WSACleanup();
            return 1;
        }
        string ip = argv[2];
        do_reverse_lookup(ip);
        WSACleanup();
        return 0;
    }


     if (first == "--raw") {
        if (argc < 3) {
            cerr << "Error: --raw requires a hostname\n";
            print_usage();
            WSACleanup();
            return 1;
        }
        string qname = argv[2];
        string dns_server = "8.8.8.8";
        if (argc >= 4) dns_server = argv[3];

        cout << "Raw DNS query for: " << qname << " via " << dns_server << "\n";
        vector<DNSAnswer> out;
        bool ok = raw_resolve_follow(qname, dns_server, out, 0);
        if (!ok) {
            cerr << "raw_resolve_follow failed\n";
            WSACleanup();
            return 1;
        }
        // Print results
        for (auto &a : out) {
            if (a.type == 1) {
                cout << "A   " << a.data_str << " (name: " << a.name << ")\n";
            } else if (a.type == 28) {
                cout << "AAAA " << a.data_str << " (name: " << a.name << ")\n";
            } else if (a.type == 5) {
                cout << "CNAME " << a.name << " -> " << a.data_str << "\n";
            }  else if (a.type == 2) {
                cout << "NS   " << a.data_str << " (zone: " << a.name << ")"
                     << " TTL: " << a.ttl << "\n";
            }
            else {
                // ignore others
            }
        }
        WSACleanup();
        return 0;
    }

    // Otherwise behave like normal hostname -> IP resolver (simple)
    const char* hostname = argv[1];

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC; // both v4 and v6
    hints.ai_socktype = 0;
    hints.ai_flags = AI_CANONNAME;

    addrinfo *result = nullptr;
    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
        cerr << "getaddrinfo: " << gai_strerrorA(status) << "\n";
        WSACleanup();
        return 1;
    }

    cout << "Results for: " << hostname << "\n";

   for (addrinfo* p = result; p != NULL; p = p->ai_next) {
    char ipStr[INET6_ADDRSTRLEN];

    void* addr;
    if (p->ai_family == AF_INET) {
        addr = &((sockaddr_in*)p->ai_addr)->sin_addr;
    } else if (p->ai_family == AF_INET6)  {
        addr = &((sockaddr_in6*)p->ai_addr)->sin6_addr;
    }
    else {
        continue;
    }

    inet_ntop(p->ai_family, addr, ipStr, sizeof(ipStr));

    std::cout << familyToStr(p->ai_family) << ": " << ipStr << "\n";
    std::cout << "  Socket Type : " << sockTypeToStr(p->ai_socktype) << "\n";
    std::cout << "  Protocol    : " << protocolToStr(p->ai_protocol) << "\n";
    std::cout << "---------------------------------------\n";
    }



    freeaddrinfo(result);
    cout << "\nPerforming MX lookup for " << hostname << "...\n";
    resolve_mx(hostname);
    // Also perform NS lookup for the given domain
    cout << "\nPerforming NS lookup for " << hostname << "...\n";
    resolve_ns(hostname);
    WSACleanup();
    return 0;
}
