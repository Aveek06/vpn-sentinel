# VPN Sentinel

A lightweight IP intelligence tool to detect VPNs, proxies, Tor nodes, and relays — built with a brutalist frontend and a Flask backend proxy.

Powered by [vpnapi.io](https://vpnapi.io).

---

## Features

- Paste multiple IPs (one per line or comma-separated)
- Detects VPN, Proxy, Tor, and Relay
- Shows country, city, and ISP for each IP
- Export flagged IPs as TXT, CSV, or JSON
- API key stays on the server — never exposed in the browser
- IPv4 and IPv6 supported

---

## Project Structure

```
VPN_Check/
├── app.py            # Flask backend proxy
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

### 2. Set the API key

```bash
# Windows
set VPNAPI_KEY=your_api_key_here

# Mac / Linux
export VPNAPI_KEY=your_api_key_here
```

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
5. Add environment variable:
   - Key: `VPNAPI_KEY`
   - Value: your vpnapi.io API key
6. Click **Deploy**

Your app will be live at `https://your-service-name.onrender.com`

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
