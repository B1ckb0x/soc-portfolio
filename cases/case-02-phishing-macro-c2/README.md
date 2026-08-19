# Case 02 — Phishing Email → Macro Execution → C2 Beaconing

**Verdict:** True Positive — Contained
**Source:** LetsDefend SOC training environment

## Alert
Inbound email from `trenton@tritowncomputers.com` delivered to host `LarsPRD` (172.16.17.57), gateway action: **Allowed/Delivered**. Attachment: `11f44531fb088d31307d87b01e8eabff.zip` containing `research-1646684671.xls`.

## Investigation
I started with the email itself: the sender domain (`tritowncomputers.com`) had no tie to any legitimate internal process, and the attachment was a zip containing an `.xls` file — that zip/xls pairing is a pattern I recognized as a common Excel 4.0 macro delivery method, so I went into the endpoint telemetry expecting to find macro activity rather than treating this as a routine attachment.

On `LarsPRD`'s process tree, I found exactly that: `excel.exe` spawning `regsvr32.exe -s ..\iroto.dll`. Excel doesn't normally launch `regsvr32` on its own — seeing Office spawn a signed system binary like that is a strong signal that a macro executed and used `regsvr32` to register a DLL, which is a known technique ("Squiblydoo") for getting a malicious payload to run under the cover of a trusted binary.

Since `regsvr32` proxy execution is often a step toward establishing outbound contact, I went straight to the proxy logs for the window right after that process ran. Sure enough, there was outbound beaconing to `nws.visionconsulting.ro` — the domain's reputation and unusual TLD, combined with the tight timing correlation to the malicious process, was enough to call this C2 traffic rather than legitimate browsing.

From there I widened the check to lateral movement and data staging, both on the host and across the surrounding network logs, and found nothing — which told me the response caught this before the attacker got further than initial access and C2 setup.

## Indicators
| Type | Value |
|---|---|
| Impacted host | LarsPRD (172.16.17.57) |
| Malicious attachment | research-1646684671.xls |
| Dropped file | iroto.dll |
| C2 domain | nws.visionconsulting.ro |
| C2 destination IP | 188.213.19.81 |

## MITRE ATT&CK Mapping
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1218.010** — System Binary Proxy Execution: Regsvr32
- **T1071** — Application Layer Protocol (C2)

## Impact
Malware executed and established C2 contact on one endpoint. No evidence of lateral movement or data exfiltration prior to containment.

## Remediation
- Isolated `LarsPRD` from the network via EDR to cut off further C2 activity.
- Hard-deleted the phishing email from the mailbox to prevent re-delivery/re-execution risk.
- Logged the file hash, C2 domain, and IP as indicators for blocklisting across the environment.
- Recommended follow-up: forensic review of the host to confirm no additional persistence mechanisms were dropped before isolation.
