# SOC Analyst Portfolio

Documented incident investigations and detection work from hands-on SOC training labs (LetsDefend) and a self-built home detection lab. I write each case up the way I'd document it in a real SOC ticketing system: what triggered the alert, how I investigated, what I concluded, and what I'd recommend.

**Background:** Computer Support Specialist (Public Trust) transitioning into SOC Analyst work. I love the investigative side of cybersecurity; the always-changing threat landscape, and stopping attacks or remediating them before data gets stolen.

**Skills demonstrated across these cases:** alert triage, log correlation, phishing analysis, malware/IOC identification, MITRE ATT&CK mapping, incident documentation, true/false positive determination.

## Home Lab
- [Detection Engineering Lab — Sysmon + Splunk + Atomic Red Team](./home-lab/) — self-built Sysmon + SIEM environment; simulated 3 MITRE ATT&CK techniques and built the Splunk detections for them

## Case Investigations

| # | Case | Type | Verdict |
|---|------|------|---------|
| 1 | [SQL Injection Attempt](./cases/case-01-sql-injection-attempt/) | Web Application Attack | True Positive — Blocked |
| 2 | [Phishing → Malicious Macro → C2 Beaconing](./cases/case-02-phishing-macro-c2/) | Phishing / Malware | True Positive — Contained |
| 3 | [Phishing → Credential Harvesting Redirect](./cases/case-03-phishing-credential-harvest/) | Phishing | True Positive — Contained |
| 4 | [Phishing → Password-Protected Malicious Attachment](./cases/case-04-phishing-password-protected-zip/) | Phishing / Malware | True Positive — Deleted |
| 5 | [Internal Email — False Alarm](./cases/case-05-false-positive-internal-email/) | Alert Tuning | False Positive |
| 6 | [Phishing — Malicious Attachment, No Execution](./cases/case-06-phishing-dormant-payload/) | Phishing | True Positive — No Impact |

Each case includes the alert details, my investigation steps, indicators of compromise, MITRE ATT&CK mapping, and remediation recommendation.
