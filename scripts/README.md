# Scripts

Everything here is run from the project root, for example `scripts/run.sh`.

## Using the app

| Script                    | Does                                                                                           |
| ------------------------- | ---------------------------------------------------------------------------------------------- |
| `setup.sh`                | one-time setup: a virtual environment and hash-checked dependencies (`--geoip` also downloads the Geo-IP database) |
| `run.sh`                  | starts the analyzer (`--replay samples/demo.pcap --loop` for the demo, `--iface en0` to pick an interface; `--help` for the rest) |
| `install_app.sh`          | builds "Network Traffic Analyzer.app" in `~/Applications` so you can start it from Spotlight (`--remove` deletes it) |
| `download_geoip.sh`       | downloads the free offline DB-IP city database used for the World tab                          |
| `macos/launcher.applescript` | the small launcher script that `install_app.sh` compiles into the app                       |

## Building and checking the project

| Script                    | Does                                                                                           |
| ------------------------- | ---------------------------------------------------------------------------------------------- |
| `vendor.sh`               | copies the browser libraries into `frontend/vendor/` and records their SHA-256 checksums       |
| `verify_vendor.sh`        | checks the vendored libraries against those checksums (CI runs it)                             |
| `world_geojson.mjs`       | builds the offline world outline; `vendor.sh` runs it                                          |

## Demo material

| Script                    | Does                                                                                           |
| ------------------------- | ---------------------------------------------------------------------------------------------- |
| `make_demo_pcap.py`       | rebuilds `samples/demo.pcap`: 90 seconds of made-up home traffic with a password sent over HTTP, a port scan and a bandwidth hog |
| `capture_screenshots.py`  | takes the README screenshots and GIF from a live capture, blurring anything private (the docstring has the commands) |
| `record_demo.py`          | records the 90-second video of the live app. It blurs other devices and checks for leaks while it records, so read its docstring before running it on your own network |
