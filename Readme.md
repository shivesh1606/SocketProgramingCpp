g++ resolver.cpp -o resolver.exe -lws2_32

Your program  
  → getaddrinfo()
       → Windows DNS Resolver
            → Router DNS (192.168.29.1)
                 → ISP DNS / External DNS
                      → Authoritative Google DNS
                           → returns A and AAAA records
