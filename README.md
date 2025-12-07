# HunterScope – IOC Enricher for Security Analysts (fully customizable)

HunterScope is a Chromium-based browser extension that lets you quickly pivot from logs, EDR consoles or tickets into your favourite **OSINT / enrichment tools**.
Its main feature is a **hover bubble** that appears when you select an IOC (IP, domain, hash) and lets you enrich it in a single click.
Additionally, it offers a configurable **right-click menu**.

# Functions:

## 🎯 Hover Bubble – One-click IOC Enrichment

The **hover bubble** is the primary way to use HunterScope.

![Animation3](https://github.com/user-attachments/assets/dd5510c5-85e9-4ee2-ac16-281a29aa9447)

### How it works

1. **Select an IOC** on any webpage:
   - An IP:  
     `8.8.8.8` or `8[.]8[.]8[.]8`
   - A domain:  
     `example.com` or `example[.]com` or part of a defanged URL like `hxxps[:]//example[.]com/login`
   - A hash:  
     `0cc175b9c0f1b6a831c399e269772661`, `da39a3ee5e6b4b0d3255bfef95601890afd80709`, etc.

2. When the selection looks like an IOC, a small **round HunterScope icon** appears next to the text.
3. On hover, it **expands** to show the label `HunterScope`.
4. On click, it performs a **Quick Analyze**:
   - Detects whether the selection is an **IP**, **domain**, or **hash**.
   - Picks the first category with a matching mode (`ip`, `domain`, `hash`).
   - Opens the IOC in **all providers** configured for that category.

### What it reacts to (and what it ignores)

The bubble **only appears** when the selected text, after refanging, is:

- ✅ An **IP address**  
  - Including defanged: `8[.]8[.]8[.]8`
- ✅ A **domain name**  
  - Including defanged: `example[.]com`, or from a defanged URL like:  
    `hxxps[:]//example[.]com/path`
- ✅ A **hash**  
  - Hex-only string with common hash lengths (e.g., 32, 40, 64 chars)

It **does not appear** for:

- Plain URLs where you want to decide the context yourself (you still have the right-click menus).
- Random sentences, usernames, or arbitrary text.

## 🖱 Right-click Context Menu

![Animation2](https://github.com/user-attachments/assets/45d891f3-07d5-4da7-8442-09f0c913eb64)

In addition to the bubble, HunterScope offers a configurable **right-click menu**.

When you right-click on a selection, link, or page, you’ll see:

- A top-level **HunterScope** entry.
- Under it, your configured **categories** (e.g. `IP`, `Domain`, `Hash`, `URL`, `CyberChef`, etc.).

Each category provides:

- **Open in all** – opens the IOC in all providers configured for that category.
- **Single provider entries** – open only that specific tool.

The right-click path still fully supports `url` mode (e.g. full URL scanners) even though the bubble focuses only on IP/domain/hash.

---

## ⚙️ Configuration & Modes

Open the Options page:

- `chrome://extensions` → **HunterScope** → **Details** → **Extension options**  
  (or left click the pinned extension icon)

<img width="1424" height="1081" alt="image" src="https://github.com/user-attachments/assets/c50891a7-b4e3-4d94-b32d-82051133692b" />

Here you can configure all OSINT analyzer categories.
I have added a few default ones based on my own preferences, but you can edit or replace them as you like.

In addition to the {val} placeholder, there is also {b64}, which automatically Base64-encodes the selected text (useful for tools like CyberChef that expect Base64 input).

# 🔧 Installation (Developer / from Source)

1. Clone or download this repository.

2. In Chrome / Edge / Brave, open:
chrome://extensions

3. Enable Developer mode.

4. Click Load unpacked and select the folder with HunterScope content.

The extension should appear in your toolbar.

