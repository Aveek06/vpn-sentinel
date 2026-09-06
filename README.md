# VPN Sentinel

A lightweight IP intelligence tool to detect VPNs, proxies, Tor nodes, and relays — built with a brutalist frontend and a Flask backend proxy.

Uses **four providers with automatic fallback** — when one hits its daily quota, the next kicks in seamlessly.

---

## Data Providers

| Priority | Provider | Free Tier | Detects |
|---|---|---|---|
| 1st | [vpnapi.io](https://vpnapi.io) | 1,000 req/day | VPN, Proxy, Tor, Relay |
| 2nd | [IPHub](https://iphub.info) | 1,000 req/day | VPN, Proxy |
| 3rd | [IPGeolocation](https://ipgeolocation.io/ip-security-api.html) | 1,000 req/day | VPN, Proxy, Tor |
| 4th | [IPLogs](https://iplogs.com) | Fair use (no key) | VPN, Proxy, Tor |

**Total free capacity: ~3,000+ IP checks/day**

When a provider exhausts its daily quota, the app automatically falls back to the next one — no restart or config change needed. IPLogs serves as an unlimited safety net.

---

## Features

- Paste multiple IPs — one per line or comma-separated
- Detects VPN, Proxy, Tor, and Relay
- Shows country, city, ISP, and which provider answered each IP
- Export flagged IPs as TXT, CSV, or JSON
- API keys stay on the server — never exposed in the browser
- IPv4 and IPv6 supported
- Rate limited: 200 IPs/min, 1,000 IPs/day per user

---

## Project Structure

```
VPN_Check/
├── app.py            # Flask backend proxy (multi-provider with fallback)
├── vpn_check.py      # CLI tool for terminal use
├── index.html        # Brutalist frontend
├── requirements.txt
└── render.yaml       # Render.com deploy config
```

---

## Local Development

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Set API keys

```bash
# Windows
set VPNAPI_KEY=your_vpnapi_key
set IPHUB_KEY=your_iphub_key
set IPGEO_KEY=your_ipgeolocation_key

# Mac / Linux
export VPNAPI_KEY=your_vpnapi_key
export IPHUB_KEY=your_iphub_key
export IPGEO_KEY=your_ipgeolocation_key
```

> IPLogs requires no key — it is used automatically as the final fallback.

### 3. Run the server

```bash
python app.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## CLI Usage

Check IPs directly from the terminal:

```bash
python vpn_check.py 1.1.1.1 8.8.8.8 104.28.0.1
```

---

## Deployment (Render.com)

1. Push this repo to GitHub (private is fine)
2. Go to [render.com](https://render.com) → **New → Web Service**
3. Connect your GitHub repo
4. Set region to **Singapore** (closest for India)
5. Add environment variables:
   - `VPNAPI_KEY` — from [vpnapi.io](https://vpnapi.io)
   - `IPHUB_KEY` — from [iphub.info](https://iphub.info)
   - `IPGEO_KEY` — from [ipgeolocation.io](https://ipgeolocation.io)
6. Click **Deploy**

> **Note:** The free tier sleeps after 15 min of inactivity. First request after sleep takes ~30 seconds to wake up.

---

## Export Formats

| Format | Contents |
|--------|----------|
| TXT | One flagged IP per line |
| CSV | IP, VPN, Proxy, Tor, Relay, Country, City, ISP |
| JSON | Full structured data array |

---

Made by **Aveek**
