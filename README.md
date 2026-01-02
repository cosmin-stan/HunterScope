# HunterScope – IOC Enricher for Security Analysts (fully customizable)

HunterScope is a Chromium-based browser extension that lets you quickly pivot from logs, EDR consoles or tickets into your favourite **OSINT / enrichment tools**.
Its core feature is a smart hover bubble that automatically detects IPs, domains, and hashes on any webpage. The extension highlights these IOCs, allowing you to hover over them and pivot to your favorite OSINT tools in a single click.
Additionally, it offers a configurable **right-click menu**.

<img width="440" height="280" alt="icon, ver2" src="https://github.com/user-attachments/assets/a8fd22d5-91da-4484-a07c-5c11ac89312c" />

# Functions:

## 🎯 Hover Bubble – One-click IOC Enrichment

The **hover bubble** is the primary way to use HunterScope.

<img width="440" height="280" alt="icon2_ver2" src="https://github.com/user-attachments/assets/fcf0638e-fdd8-469c-817a-f8c58b631135" />

![Animation](https://github.com/user-attachments/assets/e6d38757-a37b-4375-8164-720a7bab81bd)


### How it works

**1. Automatic Detection**
HunterScope actively scans the webpage and **automatically highlights** potential IOCs for you. It recognizes both standard and "defanged" formats:
* **IPs:** `8.8.8.8`, `8[.]8[.]8[.]8`
* **Domains:** `example.com`, `hxxps[:]//example[.]com/login`
* **Hashes:** MD5, SHA1, SHA256 (e.g., `0cc17...`)

**2. Hover to Enrich**
Simply move your mouse over any highlighted IOC.
* A **HunterScope bubble** will appear automatically.
* **Click the bubble** to trigger the **Quick Analyze**.

**3. Instant Analysis**
The extension detects the type (IP, Domain, Hash) and opens it in **all** your configured OSINT tools (like VirusTotal, AbuseIPDB) simultaneously.

**Please note that you can also disable the automatic hover bubble from the extension settings and you can only use the right-click options.**

### What it reacts to (and what it ignores)

- ✅ An **IP address**  
  - Including defanged: `8[.]8[.]8[.]8`
- ✅ A **domain name**  
  - Including defanged: `example[.]com`
- ✅ A **hash**  
  - Hex-only string with common hash lengths (e.g., 32, 40, 64 chars)


## 🖱 Right-click Context Menu

<img width="1518" height="649" alt="image" src="https://github.com/user-attachments/assets/b5e4c95e-a414-44a6-a1d9-bb71f94e79e8" />

![Animation2](https://github.com/user-attachments/assets/45d891f3-07d5-4da7-8442-09f0c913eb64)

In addition to the bubble, HunterScope offers a configurable **right-click menu**.

When you right-click on a selection you’ll see:

- A top-level **HunterScope** entry.
- Under it, your configured **categories** (e.g. `IP`, `Domain`, `Hash`, `CyberChef`, etc.).

Each category provides:

- **Open in all** – opens the IOC in all providers configured for that category.
- **Single provider entries** – open only that specific tool.

---

## ⚙️ Configuration & Modes

Open the Options page:

- `chrome://extensions` → **HunterScope** → **Details** → **Extension options**  
  (or left click the pinned extension icon)

<img width="910" height="772" alt="image" src="https://github.com/user-attachments/assets/ebe4c587-4bad-4e51-bced-e2370f36c3e2" />

Here you can configure all OSINT analyzer categories.
I have added a few default ones based on my own preferences, but you can edit or replace them as you like.

In addition to the {val} placeholder, there is also {b64}, which automatically Base64-encodes the selected text (useful for tools like CyberChef that expect Base64 input).

# 🔧 Installation (Developer / from Source)

<h2>Chrome Store</h2>

1. Search for 'Hunter Scope' in the Chrome Store and install it.

<img width="753" height="331" alt="image" src="https://github.com/user-attachments/assets/56481893-38c7-4e02-8dc2-3c2a1f06e879" />

<h2> Manual installation </h2>
1. Clone or download this repository.

2. In Chrome / Edge / Brave, open:
chrome://extensions

3. Enable Developer mode.

4. Click Load unpacked and select the folder with HunterScope content.

The extension should appear in your toolbar.
