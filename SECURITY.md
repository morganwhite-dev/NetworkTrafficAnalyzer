# Security

This app can see every packet on your network interface, including anything sent without encryption, so it's built to be careful with that.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (the "Report a vulnerability" button on the Security tab) instead of opening a public issue. I'll reply as soon as I can and credit you in the fix if you'd like.

## What the app does to protect you

- **Root only for a moment.** With `sudo`, it opens the capture device, switches to your user, verifies it can't switch back, and only then starts the web server. With ChmodBPF it never needs root. The Docker live-capture profile does the same thing: it starts as root only to open the socket, then drops to an unprivileged user (`NTA_DROP_UID`/`NTA_DROP_GID`), with a PID and memory limit.
- **Local only.** It binds to `127.0.0.1` and refuses other addresses unless you're in a container. Docker publishes on `127.0.0.1` only.
- **A token per launch.** The dashboard opens only through the link printed in your terminal. The token becomes an `HttpOnly`, `SameSite=Strict` cookie and is removed from the address bar. A token you set yourself with `NTA_TOKEN` must be at least 16 characters.
- **Cross-site and DNS-rebinding protection.** `Host` headers are checked, the WebSocket and every state-changing request need an exact `Origin`, and `POST` requests need a custom header that other websites can't send without permission. Browsers also tag every request with `Sec-Fetch-Site`; the API and WebSocket refuse anything that isn't `same-origin`. That matters because cookies are shared between ports on `localhost`: without this check, a web page served by some other program on your Mac (a dev server on port 3000, say) could have used the session cookie.
- **One source at a time.** Switching between Live, Demo and an uploaded file is serialised, so two quick clicks (or two tabs) can't leave demo data labelled as live. If Live can't start, the demo is put back instead of leaving an empty screen. A strip across the top says **DEMO DATA** whenever replayed traffic is on screen, and exports from a demo or an uploaded file are named `nta-demo-…` or `nta-file-…`.
- **Strict CSP.** Scripts, styles and fonts load only from the app itself. All browser libraries are vendored with SHA-256 checksums. No CDNs, no analytics, no tile servers.
- **Hostile input handling.** Uploaded captures are checked by magic bytes, size-capped while streaming, and parsed in a separate process with a timeout. Every packet is parsed inside its own error handler. Everything from the wire is shown with `textContent`, never `innerHTML`.
- **Secrets stay masked.** Detected passwords and tokens are masked in alerts, the packet table and decoded fields (masked before a long value is shortened, so a secret can't half-show at the cut), and blurred in the hex dump until you click. The blur is cosmetic: the packet's bytes are available to the authenticated dashboard, which is the same trust boundary as the token. The full export warns that it contains everything. The headers-only export cuts every packet at the end of its last parsed header (Ethernet, IP, TCP/UDP) and also zeroes any byte range flagged as a secret, so payloads never leave the app in it.
- **Privacy by default.** The Geo-IP map is offline (DB-IP). The online ip-api.com lookup is opt-in. Private, local and multicast addresses are never looked up. The one exception is on purpose: when you click a public address, the "what is this?" card asks the system's reverse DNS and `ipwho.is` (https) about that single address. Nothing is looked up in the background. `--no-ip-lookup` turns the online part off.
- **Quiet Wi-Fi check.** It never reads your network's name, and it only pings your router and `1.1.1.1` while the Wi-Fi tab is open.
- **Bounded memory.** Every buffer has a cap, so a packet flood can't exhaust memory.
- **Supply chain.** Python dependencies are hash-pinned, CI runs `pip-audit`, CodeQL and gitleaks, Actions are pinned to commit SHAs, and Dependabot keeps it all current.

## Out of scope

- Anyone who already has your user account on the Mac can read anything this app can, including a program that reads the terminal where the link was printed.
- The app is a local tool, not a hardened multi-user server. Don't expose it to a network.
