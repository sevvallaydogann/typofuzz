import json
import csv
import os
import tempfile
from datetime import datetime

class Reporter:
    def __init__(self, target: str, results: list[dict]):
        self.target = target
        self.results = results
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.safe_target = target.replace(".", "_")
        
        self.base_dir = os.path.join(tempfile.gettempdir(), "typofuzz_reports")
        os.makedirs(self.base_dir, exist_ok=True)
        print(f"\n[!] ATTENTION: Reports are being saved to this secure folder:\n    {self.base_dir}\n")

    def to_json(self) -> str:
        path = os.path.join(self.base_dir, f"typofuzz_{self.safe_target}_{self.timestamp}.json")
        payload = {
            "meta": {
                "target": self.target,
                "scan_time": datetime.now().isoformat(),
                "total_variations": len(self.results),
                "registered_count": sum(1 for r in self.results if r.get("registered")),
                "high_risk_count": sum(1 for r in self.results if r.get("risk_score", 0) >= 70),
            },
            "results": self.results,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str, ensure_ascii=False)
        return path

    def to_csv(self) -> str:
        path = os.path.join(self.base_dir, f"typofuzz_{self.safe_target}_{self.timestamp}.csv")
        fields = [
            "domain", "variation_type", "registered", "ip_address",
            "http_status", "mx_records", "ssl_valid", "ssl_issuer",
            "whois_registrar", "whois_creation_date", "recently_registered",
            "is_threat", "vt_detections", "urlhaus_status", "otx_pulses",
            "page_title", "is_parked", "risk_score",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for r in sorted(self.results, key=lambda x: x.get("risk_score", 0), reverse=True):
                row = {k: r.get(k, "") for k in fields}
                if isinstance(row.get("mx_records"), list):
                    row["mx_records"] = ", ".join(row["mx_records"])
                writer.writerow(row)
        return path

    def to_html(self) -> str:
        path = os.path.join(self.base_dir, f"typofuzz_{self.safe_target}_{self.timestamp}.html")
        html = self._render_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    def _render_html(self) -> str:
        registered = [r for r in self.results if r.get("registered")]
        high_risk = [r for r in self.results if r.get("risk_score", 0) >= 70]
        medium_risk = [r for r in self.results if 40 <= r.get("risk_score", 0) < 70]
        active_web = [r for r in self.results if r.get("http_status") and r["http_status"] < 400]
        threats = [r for r in self.results if r.get("is_threat")]

        sorted_results = sorted(self.results, key=lambda x: x.get("risk_score", 0), reverse=True)

        rows = ""
        for r in sorted_results:
            if not r.get("registered"):
                continue
            risk = r.get("risk_score", 0)
            if risk >= 70:
                risk_badge = f'<span class="badge badge-high">🔴 {risk} HIGH</span>'
                row_class = "row-high"
            elif risk >= 40:
                risk_badge = f'<span class="badge badge-med">🟡 {risk} MED</span>'
                row_class = "row-med"
            else:
                risk_badge = f'<span class="badge badge-low">🟢 {risk} LOW</span>'
                row_class = "row-low"

            http_s = r.get("http_status", "-") or "-"
            http_class = "text-green" if isinstance(http_s, int) and http_s < 300 else "text-yellow" if isinstance(http_s, int) and http_s < 400 else "text-muted"

            mx = "✅" if r.get("mx_records") else "❌"
            ssl = "✅" if r.get("ssl_valid") else "❌"
            threat = '<span class="text-danger">⚠️ THREAT</span>' if r.get("is_threat") else '<span class="text-muted">—</span>'
            registrar = r.get("whois_registrar", "—") or "—"
            if len(str(registrar)) > 25:
                registrar = str(registrar)[:25] + "…"
            ip = r.get("ip_address", "—") or "—"
            title = r.get("page_title", "—") or "—"
            if len(str(title)) > 40:
                title = str(title)[:40] + "…"

            rows += f"""
            <tr class="{row_class}">
                <td><a href="http://{r['domain']}" target="_blank" class="domain-link">{r['domain']}</a></td>
                <td><span class="vtype">{r.get('variation_type','—')}</span></td>
                <td class="{http_class}">{http_s}</td>
                <td>{mx}</td>
                <td>{ssl}</td>
                <td class="text-mono">{ip}</td>
                <td class="text-muted small">{registrar}</td>
                <td class="small">{title}</td>
                <td>{threat}</td>
                <td>{risk_badge}</td>
            </tr>"""

        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TypoFuzz Report — {self.target}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg: #0a0b0f;
    --surface: #111318;
    --border: #1e2130;
    --accent: #00d4ff;
    --red: #ff3b5c;
    --yellow: #f5c842;
    --green: #39e07d;
    --purple: #a855f7;
    --text: #e2e8f0;
    --muted: #64748b;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
  }}

  /* Header */
  .header {{
    background: linear-gradient(135deg, #0d0f1a 0%, #111827 50%, #0a0b0f 100%);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 3rem;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    top: -50%;
    left: -10%;
    width: 600px;
    height: 600px;
    background: radial-gradient(circle, rgba(0,212,255,0.05) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-top {{
    display: flex;
    align-items: center;
    gap: 1.5rem;
    margin-bottom: 1.5rem;
  }}
  .logo {{
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: var(--accent);
    text-shadow: 0 0 30px rgba(0,212,255,0.4);
  }}
  .logo span {{ color: var(--red); }}
  .header-meta {{
    font-family: 'JetBrains Mono', monospace;
    color: var(--muted);
    font-size: 0.8rem;
    line-height: 1.8;
  }}
  .target-domain {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.2rem;
    color: var(--accent);
    background: rgba(0,212,255,0.08);
    border: 1px solid rgba(0,212,255,0.2);
    padding: 0.5rem 1rem;
    border-radius: 6px;
    display: inline-block;
    margin-bottom: 0.5rem;
  }}

  /* Stats Grid */
  .stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    padding: 2rem 3rem;
    max-width: 1600px;
    margin: 0 auto;
  }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }}
  .stat-card:hover {{ border-color: var(--accent); }}
  .stat-card::after {{
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 2px;
  }}
  .stat-card.red::after {{ background: var(--red); }}
  .stat-card.yellow::after {{ background: var(--yellow); }}
  .stat-card.green::after {{ background: var(--green); }}
  .stat-card.blue::after {{ background: var(--accent); }}
  .stat-card.purple::after {{ background: var(--purple); }}
  .stat-num {{
    font-size: 2.2rem;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 0.3rem;
  }}
  .stat-card.red .stat-num {{ color: var(--red); }}
  .stat-card.yellow .stat-num {{ color: var(--yellow); }}
  .stat-card.green .stat-num {{ color: var(--green); }}
  .stat-card.blue .stat-num {{ color: var(--accent); }}
  .stat-card.purple .stat-num {{ color: var(--purple); }}
  .stat-label {{
    font-size: 0.75rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }}

  /* Table Section */
  .section {{
    padding: 0 3rem 3rem;
    max-width: 1600px;
    margin: 0 auto;
  }}
  .section-title {{
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--accent);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}
  .section-title::after {{
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }}

  table {{
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    font-size: 0.85rem;
  }}
  thead tr {{
    background: linear-gradient(to right, #0d1117, #111827);
  }}
  th {{
    padding: 0.85rem 1rem;
    text-align: left;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }}
  td {{
    padding: 0.75rem 1rem;
    border-bottom: 1px solid rgba(30,33,48,0.5);
    vertical-align: middle;
  }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: rgba(255,255,255,0.02); }}

  .row-high {{ border-left: 3px solid var(--red); }}
  .row-med {{ border-left: 3px solid var(--yellow); }}
  .row-low {{ border-left: 3px solid var(--green); }}

  .domain-link {{
    color: var(--accent);
    text-decoration: none;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.8rem;
    font-weight: 600;
  }}
  .domain-link:hover {{ text-decoration: underline; }}

  .vtype {{
    background: rgba(255,255,255,0.05);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.15rem 0.5rem;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    color: var(--muted);
    white-space: nowrap;
  }}

  .badge {{
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.25rem 0.6rem;
    border-radius: 20px;
    font-size: 0.7rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    white-space: nowrap;
  }}
  .badge-high {{ background: rgba(255,59,92,0.15); color: var(--red); border: 1px solid rgba(255,59,92,0.3); }}
  .badge-med  {{ background: rgba(245,200,66,0.12); color: var(--yellow); border: 1px solid rgba(245,200,66,0.3); }}
  .badge-low  {{ background: rgba(57,224,125,0.1); color: var(--green); border: 1px solid rgba(57,224,125,0.25); }}

  .text-green {{ color: var(--green); font-family: 'JetBrains Mono', monospace; }}
  .text-yellow {{ color: var(--yellow); font-family: 'JetBrains Mono', monospace; }}
  .text-danger {{ color: var(--red); font-weight: 700; }}
  .text-muted {{ color: var(--muted); }}
  .text-mono {{ font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; }}
  .small {{ font-size: 0.78rem; }}

  /* Footer */
  .footer {{
    text-align: center;
    padding: 2rem;
    color: var(--muted);
    font-size: 0.75rem;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
    font-family: 'JetBrains Mono', monospace;
  }}

  /* Search filter */
  .filter-bar {{
    display: flex;
    gap: 1rem;
    margin-bottom: 1rem;
    align-items: center;
  }}
  .filter-input {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.5rem 1rem;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
    outline: none;
    flex: 1;
    max-width: 400px;
    transition: border-color 0.2s;
  }}
  .filter-input:focus {{ border-color: var(--accent); }}

  .warning-box {{
    background: rgba(245,200,66,0.07);
    border: 1px solid rgba(245,200,66,0.2);
    border-radius: 10px;
    padding: 1rem 1.5rem;
    margin-bottom: 2rem;
    font-size: 0.82rem;
    color: var(--yellow);
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div class="logo">TYPO<span>FUZZ</span></div>
    <div class="header-meta">
      🎯 Typosquatting Domain Hunter & OSINT Tool v1.0.0<br>
      Phishing domain detection • Threat intelligence • Risk scoring
    </div>
  </div>
  <div class="target-domain">🎯 {self.target}</div>
  <div class="header-meta">
    Scan time: {scan_time} &nbsp;|&nbsp; Total variations: {len(self.results)} &nbsp;|&nbsp; Registered domains: {len(registered)}
  </div>
</div>

<div class="stats-grid">
  <div class="stat-card blue">
    <div class="stat-num">{len(self.results)}</div>
    <div class="stat-label">Total Variations</div>
  </div>
  <div class="stat-card red">
    <div class="stat-num">{len(registered)}</div>
    <div class="stat-label">Registered Domains</div>
  </div>
  <div class="stat-card yellow">
    <div class="stat-num">{len(active_web)}</div>
    <div class="stat-label">Active Websites</div>
  </div>
  <div class="stat-card purple">
    <div class="stat-num">{len(threats)}</div>
    <div class="stat-label">Threats Detected</div>
  </div>
  <div class="stat-card red">
    <div class="stat-num">{len(high_risk)}</div>
    <div class="stat-label">High Risk</div>
  </div>
  <div class="stat-card yellow">
    <div class="stat-num">{len(medium_risk)}</div>
    <div class="stat-label">Medium Risk</div>
  </div>
</div>

<div class="section">
  <div class="warning-box">
    ⚠️ <strong>Legal Disclaimer:</strong> This report is generated solely for authorized security testing and defensive threat intelligence. Unauthorized use may result in legal consequences.
  </div>

  <div class="section-title">📊 Registered Domains — Risk Analysis</div>

  <div class="filter-bar">
    <input class="filter-input" type="text" id="searchInput" placeholder="🔍 Filter domains..." oninput="filterTable()">
  </div>

  <table id="resultsTable">
    <thead>
      <tr>
        <th>Domain</th>
        <th>Variation Type</th>
        <th>HTTP</th>
        <th>MX</th>
        <th>SSL</th>
        <th>IP Address</th>
        <th>Registrar</th>
        <th>Page Title</th>
        <th>Threat</th>
        <th>Risk Score</th>
      </tr>
    </thead>
    <tbody>
      {rows if rows else '<tr><td colspan="10" class="text-muted" style="text-align:center;padding:2rem;">No registered domains found</td></tr>'}
    </tbody>
  </table>
</div>

<div class="footer">
  TYPOFUZZ &nbsp;•&nbsp; github.com/svvla/typofuzz &nbsp;•&nbsp; {scan_time}
</div>

<script>
function filterTable() {{
  const q = document.getElementById('searchInput').value.toLowerCase();
  const rows = document.querySelectorAll('#resultsTable tbody tr');
  rows.forEach(row => {{
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""