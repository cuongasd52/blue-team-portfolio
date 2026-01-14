# Incident report

Link to room: https://tryhackme.com/room/phishingemails5fgjlzxc
Title: Spearphishing Email delivering malicious attachment - Greenholt PLC

1. Summary: A sales executive at Greenholt PLC received an unexpected email impersonating a legitimate customer. Initial analysis confirmed a spearphishing attempt delivering a malicious attachment designed to compromise the victim system.
2. Detection

- Alert source: User-reported phishing (PhishButton)
- Detection method: Manual Review
- Trigger: unexpected customer's behavior and suspicious attachment
- Date & time: June 10 2020 05:58 UTC

3. Analysis

Email authentication

- Sender: info[@]mutawamarine[.]com
- Reply-to: info[.]mutawamarine[@]mail[.]com
- SPF: fail
- DMARC=none

Network indicators:

- Originating IP: 192[.]119[.]71[.]157
- Hosting provider: Hostwinds LLC

Attachment analysis

- Attachment: SWT\_#09674321\_**\_PDF**.CAB
- File type: RAR archive
- SHA256:2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f
- Assessment: confirmed malicious payload

4. MITRE ATT&CK Mapping

- T1566.001 – Phishing: Spearphishing Attachment

5. IoCs

- **Sender email:** info[@]mutawamarine[.]com
- **Reply-To:** info[.]mutawamarine[@]mail[.]com
- **SHA256:** 2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f
- **IP address:** 192[.]119[.]71[.]157

6. Verdict: True Positive - Spearphishing attempt to deliver a malicious attachment

7. Recommendations

- Block sender domain and reply-to domains at email gateway
- Quarantine and blacklist attachment hash
- Implement attachment type filtering for archive formats
- Perform deeper malware analysis on the attachment
- Conduct user awareness reminder on phishing indicators
