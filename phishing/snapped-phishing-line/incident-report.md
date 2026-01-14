# Incident report

https://tryhackme.com/room/snappedphishingline

### Title: Phishing campaign delivering credential harvesting payload - SwiftSpend Financial

1. Summary: Multiple employees across different departments of SwiftSpend Financial reported suspicious emails containing HTML and PDF attachments. Analysis revealed an ongoing phishing campaign delivering crendential harvesting payloads impersonating Microsoft Outlook login pages. Four users have already submitted their company account’s credentials and experienced account access issues.
2. Detection
    - Alert source: user-reported phishing
    - Detection method: manual review
    - Trigger: Multiple users unable to login after interacting with email attachments
    - Date & time: 6/29/20, 06:01 UTC
3. Analysis
    - Email authentication:
        - From: Accounts[.]Payable[@]groupmarketingonline[.]icu
        - To:
            - michael.ascot@swiftspend.finance
            - zoe.duncan@swiftspend.finance
            - derick.marshall@swiftspend.finance
            - michelle.chen@swiftspend.finance
            - william.mcclean@swiftspend.finance
        - Received from:
            - ADOUM01[.]groupmarketingonline[.]icu
            - mail1[.]groupmarketingonline[.]icu
        - Return-path: 9ZTKYQdyZIim[@]BRAEMARHOWELLS[.]COM
        - SPF: intermittent pass/fail
        - DKIM: none;
        - DMARC= none;
        
        ⇒ Findings indicate domain impersonation and misconfigured email authentication
        
    - Payload analysis
        - HTML attachments:
            - Name: Direct Credit Advice.html
            - Redirect URL: hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error
            - Further investigation revealed and embedded ZIP payload:
                - ZIP URL: hxxp[://]kennaroads[.]buzz/data/Update365[.]zip
                - File type: zip archive
                - SHA256: ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686
                - Assessment: confirmed malicious payload
        - PDF attachment:
            - Name: Quote.pdf
            - File type: PDF document
            - SHA256: 04ae3286641e71356ab3fb8e05cee0da58d94a7f6afe49620d24831db33d3441
            - Assessment: confirmed malicious file
4. MITRE ATT&CK mapping: 
    - T1566.001 - Phishing: Spearphishing Attachment
5. IoCs:
    - Sender email: Accounts[.]Payable[@]groupmarketingonline[.]icu
    - Sender mail server:
        - ADOUM01[.]groupmarketingonline[.]icu
        - mail1[.]groupmarketingonline[.]icu
    - Return-path: 9ZTKYQdyZIim[@]BRAEMARHOWELLS[.]COM
    - Malicious domain: kennaroads[.]buzz
    - **Attachment hashes:**
        - ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686
        - 04ae3286641e71356ab3fb8e05cee0da58d94a7f6afe49620d24831db33d3441
6. Verdict: true-positive - phishing campaign resulting in credential compromise.
7. Action taken (simulated)
    - Removed phishing emails
    - Malicious attachments were quarantined
    - Revoked sessions and reset compromised accounts’ password
    - Blacklist attachments’ hashes
    - Block sender domains and return-path domains
8. Recommendations
    - Enforce MFA for user accounts
    - Enhance email filtering for HTML-based phishing payloads.
    - Conduct regular phishing simulation and phishing awareness training