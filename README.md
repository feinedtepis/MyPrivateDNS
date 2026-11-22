
# NetShield 🛡️

A lightweight, locally hosted DNS filtering tool that blocks unwanted domains using customizable blocklists and allowlists. NetShield lets you filter DNS requests on your own machine and manage your filtering configuration through a local web interface.

## Features

- **DNS Filtering:** Intercepts DNS queries and blocks domains present in your blocklist.
- **Custom Blocklist:** Add domains you want to block.
- **Allowlist:** Whitelist domains to prevent them from being blocked.
- **Local Web Dashboard:** Manage and monitor your DNS filtering setup through a browser.
- **Local Hosting:** Runs on your own machine without relying on an external filtering service.
- **Customizable:** Modify your blocklist and allowlist according to your needs.

## Requirements

- Python 3.10+
- Windows, Linux, or macOS
- Administrator/root privileges may be required to bind to port 53 or configure your system DNS.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/feinedtepis/NetShield.git
cd NetShield
```

### 2. Create a virtual environment

**Windows:**

```powershell
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

If a requirements file is not provided:

```bash
pip install dnslib
```

## Running NetShield

Open two terminals inside the project directory.

### Terminal 1 — DNS Server

Activate your virtual environment, then run:

```bash
python dns_server.py
```

### Terminal 2 — Web Interface

Activate your virtual environment and run:

```bash
python web.py
```

Open the local dashboard in your browser using the address displayed by the web server (commonly `http://127.0.0.1:5000`).

## Configuration

### Blocklist

The `blocklist.txt` file contains domains you want NetShield to block.

Add one domain per line:

```text
example-ad.com
tracking-site.com
unwanted-domain.com
```

### Allowlist

The `allowlist.txt` file contains domains that should be allowed even if they match a blocklist entry.

```text
trusted-site.com
example-ad.com
```

Make sure the domain format follows the project's expected format.

## Using NetShield on Your Machine

To filter DNS traffic from your own device:

1. Start the NetShield DNS server.
2. Make sure the DNS server is running and listening on the intended interface and port.
3. Configure your device's DNS server address to point to the machine running NetShield.
4. Test DNS resolution using a tool such as `nslookup`.
5. Use the dashboard and list files to manage filtering rules.

> **Note:** DNS configuration varies by operating system. Changing your DNS settings may affect your ability to access websites if NetShield is stopped.

## Testing

You can test DNS resolution with:

```bash
nslookup example.com 127.0.0.1
```

Replace `127.0.0.1` with the address of the machine hosting NetShield if you're testing from another device.

If a domain is blocked, it should return the blocking response configured by NetShield instead of resolving normally.

## Troubleshooting

### DNS server fails to start

- Check whether port 53 is already in use.
- Run with elevated privileges if required.
- Make sure your virtual environment is activated and dependencies are installed.

### Websites are not being blocked

- Verify that the domain is present in `blocklist.txt`.
- Check whether it is also present in `allowlist.txt`.
- Make sure your device is actually using NetShield as its DNS server.
- Clear your DNS cache after changing DNS settings.

### Dashboard is inaccessible

- Confirm that `web.py` is running.
- Verify the local address and port printed by the application.
- Check that your firewall isn't blocking access.

## Disclaimer

NetShield is a locally hosted project intended for educational and personal use. DNS filtering may not block all ads, trackers, or unwanted content. Some applications use encrypted DNS or other techniques that may bypass local DNS filtering.
<img width="1857" height="927" alt="Screenshot 2026-11-18 133008" src="https://github.com/user-attachments/assets/0b2e6a7d-64d3-4a05-af8a-cb5467dd7745" />


## Contributing

Contributions, suggestions, and bug reports are welcome. Feel free to fork the repository and submit a pull request.

## License

See the repository's license for terms of use.


