# Troubleshooting

## "Live capture unavailable" banner

The app can't read `/dev/bpf*`. Pick one:

```bash
brew install --cask wireshark-chmodbpf
```

Then log out and back in (the group membership only applies to new sessions) and run `scripts/run.sh` again.

Or run the app with sudo. It opens the capture device as root and then drops back to your user before serving anything:

```bash
sudo scripts/run.sh
```

## "Root was dropped at startup" when switching interfaces

Under sudo, only the interface opened at startup can be captured (after that the app is no longer root). Restart with the one you want:

```bash
sudo scripts/run.sh --iface en5
```

ChmodBPF doesn't have this limitation.

## The page says it's locked

The dashboard only opens through the link printed in your terminal, which has a one-time token in it. That stops other websites, and other users on the same Mac, from reading your traffic through `localhost`. Copy the link again from the terminal. A new token is made every time the app starts.

## Which interface should I use?

| Interface       | What it is                                 |
| --------------- | ------------------------------------------ |
| `en0`           | Wi-Fi on most Macs (this is the default)   |
| `en5`, `en6`…   | USB or Thunderbolt Ethernet adapters       |
| `utun0`–`utunN` | VPN tunnels (and some system services)     |
| `lo0`           | Loopback, traffic between apps on this Mac |
| `awdl0`, `llw0` | AirDrop and Continuity, mostly noise       |

To check for VPN leaks, capture on `en0` while your VPN is connected. You should see almost everything going to your VPN server. Anything else is flagged as a possible leak.

## No dots on the world map

Run `scripts/download_geoip.sh` once to get the offline DB-IP database, then restart. Or start with `--geo ip-api` to use the online service (it sends public IP addresses to ip-api.com over plain HTTP, so it's off by default). Private and local addresses never get a location, so a capture of only home traffic has an empty map.

## Python version problems

The app needs Python 3.11 or newer and is developed on 3.14. If `scripts/setup.sh` picks the wrong Python, point it at the right one:

```bash
PYTHON=/opt/homebrew/bin/python3.14 scripts/setup.sh
```

## Docker on a Mac shows no live traffic

That's expected. Docker Desktop runs containers inside a Linux virtual machine, so a container can't see your Mac's network interfaces. Use Docker for the demo and for analysing `.pcap` files. For live capture on a Mac, run the app directly. On a Linux machine, `docker compose --profile linux-capture up capture` does capture the host's interfaces.

## "Packets dropped"

If you hover the packet counter and see dropped packets, the app couldn't keep up (very fast downloads on a busy machine). Dropped packets are only missing from the dashboard, not from the network. Capturing on a less busy interface, or closing other tabs of the dashboard, helps.

## Uploaded file is rejected

Only classic `.pcap` and `.pcapng` are accepted, up to 200 MB. Compressed captures (`.pcap.gz`) are refused on purpose, so unzip them first. Files with mixed link types keep the first type and report how many packets were skipped.
