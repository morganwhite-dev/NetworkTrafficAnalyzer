# What gets flagged

Every detector works from packet timestamps, so an uploaded `.pcap` produces the same alerts as the live capture it came from. Each alert has a cooldown so the same thing isn't reported over and over. While an incident is still happening (a scan in progress, a hog still downloading), the existing alert updates in place instead.

A flagged host turns red on the map (amber for medium) and stays that way for 5 minutes after its last alert.

| Detector                   | Fires when                                                                                                                                                          | Severity                                                                            | Turns red                                   |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------- |
| **Port scan**              | one source has 20+ failed probes to 20+ ports within 10 s. "Failed" means the SYN got a RST, or got no answer within 2 s, or a UDP probe got ICMP port-unreachable. | high                                                                                | the scanner                                 |
| **Host sweep**             | one source probes 20+ different hosts on your subnet within 10 s, or sends ARP who-has for 20+ addresses                                                            | high                                                                                | the scanner                                 |
| **Cleartext credentials**  | a client sends a password, token, `Authorization` header, cookie or login over HTTP, FTP, POP3, IMAP or SMTP before `STARTTLS`                                      | critical (passwords, auth) or high                                                  | the server it was sent to                   |
| **Telnet session**         | any Telnet traffic                                                                                                                                                  | low                                                                                 | the server                                  |
| **Traffic spike**          | total throughput stays above the 10-minute average + 3σ, and above 1 MB/s, for 5 seconds                                                                            | medium                                                                              | none (the top talker is named in the alert) |
| **Bandwidth hog**          | one host carries 60%+ of traffic at 2 MB/s+ for 10 seconds                                                                                                          | high, or info for well-known services (Apple, CDNs, YouTube, Netflix, Zoom, Steam…) | the host                                    |
| **ARP / NDP spoofing**     | your gateway's MAC address changes, or any address flips MACs twice in 60 s                                                                                         | high                                                                                | the address and the device that claimed it  |
| **MAC address changed**    | an address moves to a new MAC once (usually DHCP or Private Wi-Fi Address)                                                                                          | low                                                                                 | none                                        |
| **Possible DNS tunneling** | 30+ unique subdomains of one domain in 60 s, or 20+ very long, high-entropy, TXT or NULL queries                                                                    | medium                                                                              | the querying device                         |
| **Rogue DHCP server**      | more than one DHCP server answers within 10 minutes                                                                                                                 | high                                                                                | the newest server                           |
| **Rogue IPv6 router**      | more than one router advertisement source within 10 minutes                                                                                                         | high                                                                                | the newest router                           |
| **Possible VPN leak**      | live capture on a physical interface while a `utun` VPN owns the default route, and an internet host other than the VPN server gets 5+ packets                      | high                                                                                | the host that leaked                        |

## Slow network and heavy use (live capture only)

These come from the Wi-Fi tab's readings, which keep running every 5 s during a live capture (every 2 s while the tab is open), and from this Mac's own traffic. Each one says whether **this Mac** is the cause. They live in `backend/app/health.py`.

| Alert                     | Fires when                                                                                                       | Severity                                                      |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| **Slow Wi-Fi**            | the Wi-Fi check says "weak signal" or "busy" for 10 s (router 40 ms+ or losing 5%+ of pings)                     | medium                                                        |
| **Slow internet**         | the router answers quickly but the internet past it is 120 ms+ slower, or drops 3%+ of pings, for 10 s           | medium                                                        |
| **Wi-Fi hiccups**         | the router spikes to 50 ms+ twice or more in a minute, for 10 s                                                  | low                                                           |
| **Heavy bandwidth use**   | this Mac moves 3 MB/s+ for 15 s. It names the app (from `lsof`, your own apps only) and the server               | medium if the network got slower at the same time, else low |

"This Mac is the cause" means it is moving 2 MB/s+ (or half its Wi-Fi link) at the time. Each alert is marked **ENDED** once things have been normal for 20 s (heavy use: under 1 MB/s for 10 s); if it comes back within 10 minutes the same alert opens again. Traffic spikes and bandwidth hogs are marked ended too, with their peak numbers.

The Mac can only see its own traffic on Wi-Fi, so "not this Mac" means "the network, or another device on it": the app can't tell which other device.

## Tuning

The thresholds live as plain numbers at the top of each check in [`backend/app/detectors.py`](../backend/app/detectors.py). The tests in `backend/tests/test_detectors.py` feed crafted traffic through every detector, including "normal browsing is not a scan" and "CDN names aren't tunneling", so you can change a number and see what breaks.

## Things that look scary but usually aren't

- **Bandwidth hog on a known service** is reported as `info`: big macOS updates, iCloud sync, Time Machine to a NAS and streaming all look like hogs.
- **MAC address changed** happens when phones rotate their Private Wi-Fi Address.
- **Many hosts on port 443** is just a web page loading, so host-sweep only counts your own subnet and only failed attempts.
- **Bonjour and SSDP** (5353, 1900) are ignored by the scan detector.

## Blind spots

Some things this app can't see, by design of the protocols:

- **DNS over HTTPS** (Chrome, Firefox, iCloud Private Relay) hides DNS queries completely, so the tunneling detector and host names from DNS go quiet.
- **iCloud Private Relay** sends Safari traffic to Apple's relay, so the "host" you see is the relay ingress (`mask.icloud.com`), not the website.
- **Encrypted Client Hello** hides the TLS server name, so some hosts show up as plain IPs.
- **Credentials split across TCP segments** aren't reassembled (reassembly is turned off on purpose for safety), so a very large login form can slip past.
- **On a VPN interface (`utun`)** there are no MAC addresses, so ARP checks are off.
