# Security

This app can see every packet on your network interface, including anything sent without encryption, so it's built to be careful with that.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (the "Report a vulnerability" button on the Security tab) instead of opening a public issue. I'll reply as soon as I can and credit you in the fix if you'd like.

## What the app does to protect you

- **Root only for a moment.** With `sudo`, it opens the capture device, switches to your user, verifies it can't switch back, and only then starts the web server. With ChmodBPF it never needs root.
- **Local only.** It binds to `127.0.0.1` and refuses other addresses unless you're in a container. Docker publishes on `127.0.0.1` only.
- **A token per launch.** The dashboard opens only through the link printed in your terminal. The token becomes an `HttpOnly`, `SameSite=Strict` cookie and is removed from the address bar.
- **Cross-site and DNS-rebinding protection.** `Host` headers are checked, the WebSocket and every state-changing request need an exact `Origin`, and `POST` requests need a custom header that other websites can't send without permission.
- **Strict CSP.** Scripts, styles and fonts load only from the app itself. All browser libraries are vendored with SHA-256 checksums. No CDNs, no analytics, no tile servers.
- **Hostile input handling.** Uploaded captures are checked by magic bytes, size-capped while streaming, and parsed in a separate process with a timeout. Every packet is parsed inside its own error handler. Everything from the wire is shown with `textContent`, never `innerHTML`.
- **Secrets stay masked.** Detected passwords and tokens are masked in alerts, the packet table and decoded fields, and blurred in the hex dump until you click. Exports warn that they contain everything and offer a headers-only version.
- **Privacy by default.** Geo-IP is offline (DB-IP). The online ip-api.com lookup is opt-in. Private, local and multicast addresses are never looked up.
- **Bounded memory.** Every buffer has a cap, so a packet flood can't exhaust memory.
- **Supply chain.** Python dependencies are hash-pinned, CI runs `pip-audit`, CodeQL and gitleaks, Actions are pinned to commit SHAs, and Dependabot keeps it all current.

## Out of scope

- Anyone who already has your user account on the Mac can read anything this app can.
- The app is a local tool, not a hardened multi-user server. Don't expose it to a network.
