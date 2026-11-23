"""A pre-built demo case (all data fictional) so the workspace can be shown instantly,
with no AI call and no network. Loaded by the "Load demo case" button."""

DEMO_CASE_ID = "IR-2026-0142"

_ENTRIES = [
    {
        "submitted": "09:12", "event_time": "09:12", "severity": "medium",
        "title": "Phishing email delivered",
        "summary": "A spoofed IT Helpdesk message reached nurse.kim. SPF and DMARC both failed, yet the gateway delivered it because it is in monitor-only mode.",
        "indicators": [
            {"type": "ip", "value": "198.51.100.23"},
            {"type": "domain", "value": "northbridge-health-helpdesk.example"},
            {"type": "email", "value": "it-support@northbridge-health-helpdesk.example"},
            {"type": "user", "value": "nurse.kim"},
        ],
        "next_steps": ["Pull the message from every mailbox", "Check who else received it",
                       "Block the sender domain and the sending IP", "Ask Nurse Kim whether she clicked the link"],
        "note": "Nurse Kim reported a password-expiry email from IT Helpdesk. SPF fail, DMARC fail. Escalating.",
    },
    {
        "submitted": "09:18", "event_time": "09:18", "severity": "high",
        "title": "Credentials submitted to a lookalike page",
        "summary": "WS-114 posted to a fake login page at northbridge-login.example right after the email arrived. Nurse Kim's credentials should be treated as stolen.",
        "indicators": [
            {"type": "url", "value": "hxxps://northbridge-login[.]example/reset"},
            {"type": "ip", "value": "198.51.100.77"},
            {"type": "host", "value": "WS-114"},
            {"type": "user", "value": "nurse.kim"},
        ],
        "next_steps": ["Reset nurse.kim's password and revoke sessions", "Block northbridge-login.example at the proxy",
                       "Search proxy logs for other users who visited it"],
        "note": "Proxy shows POST from WS-114 to northbridge-login.example/reset at 09:18, status 200.",
    },
    {
        "submitted": "09:41", "event_time": "09:41", "severity": "high",
        "title": "Foreign sign-in succeeded without MFA",
        "summary": "After three failures from Bucharest, 203.0.113.45 signed in as nurse.kim over legacy authentication, so MFA never triggered.",
        "indicators": [
            {"type": "ip", "value": "203.0.113.45"},
            {"type": "user", "value": "nurse.kim"},
        ],
        "next_steps": ["Revoke every nurse.kim session and token", "Disable legacy authentication for the tenant",
                       "Review mailbox rules and forwarding created after 09:41", "Check other sign-ins from 203.0.113.45"],
        "note": "Three failed logins then success from 203.0.113.45 (Bucharest, RO). Legacy auth, MFA not required.",
    },
    {
        "submitted": "09:55", "event_time": "09:55", "severity": "critical",
        "title": "Remote PowerShell on the EHR server",
        "summary": "Encoded PowerShell ran on SRV-EHR-02 through remote WMI from WS-114, under nurse.kim's account. This is lateral movement toward the records system.",
        "indicators": [
            {"type": "host", "value": "SRV-EHR-02"},
            {"type": "host", "value": "WS-114"},
            {"type": "process", "value": "powershell.exe"},
        ],
        "next_steps": ["Isolate SRV-EHR-02 and WS-114 from the network", "Capture memory and the decoded command line",
                       "Hunt for the same WMI pattern on other servers", "Notify the EHR system owner now"],
        "note": "EDR HIGH on SRV-EHR-02: powershell -nop -w hidden -enc ..., parent wmiprvse.exe, remote WMI from 10.20.8.31 (WS-114). Detect only, not blocked.",
    },
    {
        "submitted": "10:20", "event_time": "10:20", "severity": "critical",
        "title": "412 MB sent to an external IP",
        "summary": "SRV-EHR-02 sent 412 MB to 203.0.113.99 in six minutes, against a baseline of about 2 MB a day. The server holds ePHI, so this is a likely data breach.",
        "indicators": [
            {"type": "ip", "value": "203.0.113.99"},
            {"type": "domain", "value": "cdn-sync-update.example"},
            {"type": "host", "value": "SRV-EHR-02"},
        ],
        "next_steps": ["Block 203.0.113.99 and cdn-sync-update.example at the firewall", "Preserve firewall and EDR logs as evidence",
                       "Engage privacy and legal for a breach assessment", "Start the HIPAA breach-notification review"],
        "note": "Firewall: three large outbound sessions from 10.20.5.12 to 203.0.113.99:443, total 412 MB in 6 min. DNS for cdn-sync-update.example first seen today.",
    },
]


def demo_entries(analyst=None):
    return [{**e, "image": None, "analyst": analyst} for e in _ENTRIES]
