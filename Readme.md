g++ resolver.cpp -o resolver.exe -lws2_32

Your program  
  → getaddrinfo()
       → Windows DNS Resolver
            → Router DNS (192.168.29.1)
                 → ISP DNS / External DNS
                      → Authoritative Google DNS
                           → returns A and AAAA records

✔️ So reverse DNS =

Look up the PTR record for an IP inside the special in-addr.arpa zone.

Real simple analogy

Think of DNS like a phonebook:

Forward lookup

You know a person’s name → you get their phone number
✔️ Everyone has one

Reverse lookup

You have a phone number → you ask: “Whose number is this?”
❌ Works only if they added their name to the reverse phonebook

Most people don’t.



🎯 Long Answer (Clear Explanation)

When you call:

getaddrinfo("google.com", NULL, &hints, &result);


You are NOT connecting to Google.
You are NOT asking Google which protocols it supports.

You are simply asking your OS:

“Hey OS, if I want to connect to google.com, what IPs and socket types/protocols should I use?”


🔥 Let’s simplify with a real-world analogy

Imagine you want to visit someone’s house.

You ask someone:

“How do I reach this house?”

They reply:

Here is the address (IP)

Use a car (TCP)

Take a highway (stream socket)

This does not mean the person living inside uses a car.
It means you must use a car to go there.

Same with networking:

IP = house address

Socket type = vehicle type

Protocol = type of road

getaddrinfo() is telling you how to reach the server, not what the server internally uses.


🧠 Why does nslookup show more info?

Because nslookup is a DNS client.

It knows:

DNS queries are made via UDP

DNS fallback uses TCP if packet is large

❗ Notice something important:

The server (Google, Cloudflare, etc.) does not tell you this directly.

Your OPERATING SYSTEM knows:

“DNS = UDP”

“HTTP = TCP”

“SSH = TCP”

“Ping = raw ICMP”

And based on these rules, OS gives you the right connection recipe.

CNAME Resolution (Canonical Name)

When you visit:

www.youtube.com


The DNS server may internally map it to another domain:

youtube-ui.l.google.com


This "true" domain is called the canonical name (CNAME).

Your resolver can print this using:

AI_CANONNAME flag

reading ai_canonname field


Important:
Out existing code uses getaddrinfo() → this already handles CNAME internally, so you never actually see the CNAME.
So we need to use Raw Dns query function


🚀 6. So what purpose does CNAME solve?
✔ Makes domain point to a dynamic backend
✔ Allows cloud providers to rotate IPs
✔ Lets you use CDNs easily
✔ Lets you “alias” your domain to another
✔ Reduces maintenance
✔ Allows www to stay stable forever


🏁 Summary in 4 Lines

CNAME = nickname → tells DNS to look at another domain for the real location

Used because cloud services change server IPs frequently

www works because you added CNAME for www

root domain doesn’t work because it needs an A/AAAA record, not CNAME