#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

using std::string;
using std::cout;
using std::cerr;
using std::endl;

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
}
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
    } else {
        addr = &((sockaddr_in6*)p->ai_addr)->sin6_addr;
    }

    inet_ntop(p->ai_family, addr, ipStr, sizeof(ipStr));

    std::cout << familyToStr(p->ai_family) << ": " << ipStr << "\n";
    std::cout << "  Socket Type : " << sockTypeToStr(p->ai_socktype) << "\n";
    std::cout << "  Protocol    : " << protocolToStr(p->ai_protocol) << "\n";
    std::cout << "---------------------------------------\n";
    }


    freeaddrinfo(result);
    WSACleanup();
    return 0;
}
