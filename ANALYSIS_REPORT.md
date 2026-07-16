# Malware Analysis Report: CRX Extractor/Downloader (Chrome/Edge extension)

**Report ID:** CRX-EXT-2026-07-15 · **Analyst:** Cowork (defensive analysis) · **Date:** 2026-07-15
**Classification:** TLP:CLEAR
**Severity:** **Benign — Low risk** (legitimate dual-use developer tool)

> Network indicators below are **defanged** (`hxxp`, `[.]`) and all code is
> discussed as **inert evidence**. Nothing in the sample was executed.

## 1. Executive summary

This is a **legitimate, unpacked Manifest V3 browser extension** whose stated and
actual purpose is to download a Chrome/Edge Web Store extension's package (`.crx`)
and optionally convert it to `.zip`. The code does exactly what it advertises,
using Google's and Microsoft's own public CRX-download endpoints. There is **no
obfuscation, no data collection, no covert network exfiltration, no credential
access, and no dynamic/remote code execution**. The only mildly noteworthy
behaviors are ordinary marketing/telemetry touches (an on-install info page and
an uninstall-feedback URL pointing to the developer's own site). Recommended
action: treat as an allowed developer/research utility; no containment required.
The one thing worth understanding is that the tool is **dual-use** — the ability
to pull any store extension's source is normal for researchers but should be
governed by policy in sensitive environments.

## 2. Sample identification

Analyzed as a folder of unpacked extension source (not a packed `.crx`).

| Attribute | Value |
|-----------|-------|
| Artifact | Unpacked MV3 Chrome/Edge extension folder |
| Name / version | CRX Extractor/Downloader — v1.5.9 (per `manifest.json`) |
| File type (true) | Plain-text JS/HTML/JSON + PNG icons (magic-byte confirmed) |
| Packing / obfuscation | None; entropy ~4.9–5.1 (normal for source) |
| Store identity (Chrome) | `ajkhmmldknmfjnmeedkbkkojgobmljda` |
| Store identity (Edge) | `gfgehnhkaggeillajnpegcanbdjcbeja` |

File hashes (SHA-256):

| File | Size | SHA-256 |
|------|------|---------|
| `manifest.json` | 4 KB | `753ffdcb0c19930ccaecc4ecc032a025a845b8ab123ecdd3c96a497ad4cff96a` |
| `background.js` | 6,829 B | `3afa6536a1123a9a7457a7d863a1c3b1ea84182ffff21661ea644fdc6a2a8ee8` |
| `popup.js` | 4,107 B | `6299fe6a88e4fc949ec19fc24d3842c335b50b352acdc8624b37e5158b4746f3` |
| `popup.html` | 4 KB | `18002ada25b588def5f98e98926ec46a744e12bc35433033e499ba1aa25de249` |
| `README.md` | 4 KB | `b7d985cd4d7981ade573ddcd4da52b43231d4db426dd288a1f823c2304c8ada6` |

## 3. Static analysis findings

**`manifest.json`** — MV3. Permissions: `downloads`, `contextMenus`, `activeTab`
(`downloads` is listed twice — a harmless authoring duplication, not a security
issue). `host_permissions` are tightly scoped to the two Google CRX hosts
(`clients2.google.com/service/update2/crx*` and
`clients2.googleusercontent.com/crx/download/*`). No `<all_urls>`, no broad host
access, no content scripts, no remote code. This is a **least-privilege**
manifest for what the tool does.

**`background.js`** — the core logic:
- Three regexes extract a 32-char extension ID from Chrome (`chrome.google.com`,
  `chromewebstore.google.com`) and Edge (`microsoftedge.microsoft.com`) store
  URLs.
- On a context-menu click (or popup message), it builds the **official** CRX
  download URL for the detected ID and Chrome version, e.g.
  `hxxps://clients2.google[.]com/service/update2/crx?...x=id%3D<extID>...` (Google)
  or `hxxps://edge.microsoft[.]com/extensionwebstorebase/v1/crx?...` (Edge).
- `convertURLToZip()` / `ArrayBufferToBlob()` fetch the CRX, then **parse the CRX
  header** (magic number + CRX version + public-key/signature lengths) to compute
  the offset where the embedded ZIP begins, and slice it out. This is legitimate
  CRX-format handling, not tampering.
- `chrome.downloads.download({ ... saveAs: true })` saves the file **with a user
  save dialog** — the user is always in the loop; nothing is written silently.
- `setUninstallURL(...)` and an on-install `chrome.tabs.create(...)` open pages on
  `thebyteseffect[.]com` (the developer's site). Standard onboarding/feedback
  behavior; a mild privacy note, not malicious.

**`popup.js` / `popup.html`** — UI wiring: two download buttons that message the
background worker, a **client-side** CRX→ZIP converter (reads a local file via
`FileReader`, strips the CRX header in-browser, saves the ZIP — no network), and a
"Rate Us" link to the Web Store listing. No `eval`, no `Function()`, no
`fromCharCode`/`atob` decoding, no injected remote scripts.

**Conclusion of static analysis:** a small, readable, single-purpose utility. Its
capability is bounded by its narrow permissions, and every network call targets a
first-party Google/Microsoft endpoint or the developer's own info pages. High
confidence in the benign assessment.

## 4. Behavior analysis

Observed behavior end to end: user navigates to a Web Store detail page → extension
extracts the extension ID → on user action, fetches that extension's official CRX
from Google/Microsoft → converts to ZIP if requested (header stripped) → prompts
the user to save. Secondary behavior: opens a developer info page on first install
and a feedback page on uninstall. No persistence beyond the normal extension
lifecycle, no background beaconing, no reading or modifying of arbitrary page
content (there are no content scripts), no access to cookies/credentials/storage
of other sites.

## 5. MITRE ATT&CK mapping

No adversarial techniques were observed. For completeness, the closest *dual-use*
mapping (benign here, listed only so a defender understands the capability class):

| Tactic | Technique ID | Technique Name | Evidence |
|--------|--------------|----------------|----------|
| — (dual-use) | T1005 (contextual only) | Data from Local System — *inverted*: retrieves publicly-available store packages, not local victim data | `background.js` CRX fetch; **not** malicious use |
| Malicious techniques | None | None observed | — |

No persistence, privilege escalation, defense evasion, credential access, C2, or
exfiltration techniques are present.

## 6. Indicators of Compromise (IOCs)

These are **benign identifying indicators** (useful for asset inventory / to
distinguish the genuine extension from a trojanized copy), not threat IOCs.

**Hashes** — see §2.

**Network** (defanged; all first-party or developer-owned)

| Type | Value | Notes |
|------|-------|-------|
| Endpoint | `hxxps://clients2.google[.]com/service/update2/crx` | Official Google CRX endpoint |
| Endpoint | `hxxps://clients2.googleusercontent[.]com/crx/download/` | Official Google CRX host |
| Endpoint | `hxxps://edge.microsoft[.]com/extensionwebstorebase/v1/crx` | Official Edge CRX endpoint |
| Developer site | `thebyteseffect[.]com` | Install info + uninstall feedback pages |

**Host-based**

| Type | Value | Notes |
|------|-------|-------|
| Chrome store ID | `ajkhmmldknmfjnmeedkbkkojgobmljda` | Genuine listing |
| Edge store ID | `gfgehnhkaggeillajnpegcanbdjcbeja` | Genuine listing |
| Permissions | `downloads`, `contextMenus`, `activeTab` | Least-privilege set |

## 7. Detection

A **threat** detection rule is **not warranted** — this is benign software.
Provided instead is an **identification** YARA rule (asset inventory / to flag a
*modified* copy whose behavior diverges from this baseline). Sigma is **not
applicable** — there is no malicious log-observable activity to detect.

### YARA (identification, not threat detection)
```yara
rule Identify_CRX_Extractor_Downloader
{
    meta:
        description = "Identifies the benign 'CRX Extractor/Downloader' extension source (baseline v1.5.9)"
        author      = "defensive-analysis"
        date        = "2026-07-15"
        purpose     = "asset inventory / detect tampered copies, NOT malware detection"
        severity    = "informational"

    strings:
        $a = "extensionwebstorebase/v1/crx" ascii
        $b = "service/update2/crx?response=redirect" ascii
        $c = "thebyteseffect.com/posts/reason-for-uninstall-crx-extractor" ascii
        $d = "ArrayBufferToBlob" ascii

    condition:
        3 of ($a, $b, $c, $d)
}
```
**False-positive note:** this intentionally matches the legitimate extension. Its
value is the inverse — if this extension is present but this rule *fails* (strings
changed) while the extension still claims to be CRX Extractor, that divergence
warrants a closer look at a possibly repackaged copy.

### Sigma
None — no malicious behavior to detect.

## 8. Recommendations & containment

No containment is required. Practical guidance: (1) treat as an approved
developer/research utility; (2) if operating in a sensitive/enterprise
environment, be aware the tool is **dual-use** (it can pull any store
extension's source) and govern it by policy rather than by threat response;
(3) prefer installing from the official Chrome/Edge store listings (IDs in §6) so
updates are signed, rather than side-loading unpacked copies; (4) if you ever
encounter a copy of this extension that requests broader permissions (content
scripts, `<all_urls>`, `tabs`, `webRequest`) or contains obfuscated code, treat
*that* copy as suspicious and re-analyze — it would not match this clean baseline.

## 9. Appendix

- **Tooling:** static review only (hashing, magic-byte typing, entropy, string
  extraction via `triage.py`, manual source reading). The sample was **never
  executed**.
- **Limitations:** analysis covers the on-disk unpacked source provided. It does
  not cover any server-side content served by `thebyteseffect[.]com` or the
  behavior of the *target* extensions a user chooses to download (those are
  separate artifacts and out of scope).
- **Open questions:** none material to the verdict.
