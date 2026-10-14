# Case 08 — Phishing Email → Fake Webmail Login

**Verdict:** True Positive — Contain and escalate
**Date:** 29 Aug 2024
**Source:** Published phishing email and packet capture, Malware-Traffic-Analysis.net (2024-08-29)

## Alert
Inbound message asking the recipient to re-authenticate a mailbox. The link host was not the sender's domain and not the recipient's domain.

## Investigation
The visible sender was `SupportDesk <khz.port@scp.gov.iq>`, addressed to `admin@malware-traffic-analysis.net`, with the subject `Account Validation!! For admin@malware-traffic-analysis.net Only!!`

The authentication headers failed closed:

- `spf=fail`. The sending IP `188.127.247.252` (`s940027.srvape.com`) is not authorized to send for `scp.gov.iq`.
- `dkim=none`.
- `dmarc=fail`, reason `No valid SPF, No valid DKIM`, policy `quarantine`.
- The receiving gateway set `X-Recommended-Action: reject`.

An earlier hop showed the message originating at `ip172.ip-149-56-149.net` before the srvape relay. The body told the recipient to click a button and type their email password. The link was:

`https://email.procedure.best/management.aspx?good=admin@malware-traffic-analysis.net`

That host is not `scp.gov.iq` and not `malware-traffic-analysis.net`. I checked the domain on urlscan.io. There was no stored scan, so the verdict does not depend on a vendor score.

The packet capture for the same case shows the follow-up. The browser loaded the login page over HTTP, then sent an HTTP POST to `email.procedure.best` with content type `application/x-www-form-urlencoded`. The body contained a password field. I am not publishing the submitted value.

## Indicators
| Type | Value |
|---|---|
| Sender | khz.port@scp.gov.iq (display name SupportDesk) |
| Sending IP | 188.127.247.252 |
| Relay | s940027.srvape.com |
| Earlier hop | ip172.ip-149-56-149.net |
| Login host | email.procedure.best |
| URL path | /management.aspx |

## MITRE ATT&CK Mapping
- **T1566.002** — Phishing: Spearphishing Link

## Impact
The password for the addressed mailbox should be treated as exposed. The capture shows the form was submitted.

## Remediation
- Block `scp.gov.iq` as a sending domain and block `email.procedure.best` at the mail gateway and the web proxy.
- Reset the exposed mailbox password and revoke existing sessions.
- Escalate to incident response because a credential was submitted, not merely because a link was delivered.

## Reference
https://www.malware-traffic-analysis.net/2024/08/29/index.html
