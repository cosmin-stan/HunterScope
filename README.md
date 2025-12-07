# HunterScope – IOC Enricher for Security Analysts

HunterScope is a Chromium-based browser extension that lets you quickly pivot from logs, EDR consoles or tickets into your favourite **OSINT / enrichment tools**.
Its main feature is a **hover bubble** that appears when you select an IOC (IP, domain, hash) and lets you enrich it in a single click. Classic right-click context menus and a fully configurable backend sit behind it.

# Functions:

## 🎯 Hover Bubble – One-click IOC Enrichment

The **hover bubble** is the primary way to use HunterScope.



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
