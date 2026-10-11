export interface RawDemoCase {
  caseId: string;
  caseNumber: string;
  title: string;
  category: string;
  description: string;
  analyst: string;
  rawEmail: string;
}

export const DEMO_CASE_1_LEGITIMATE: RawDemoCase = {
  caseId: 'CASE-2026-001',
  caseNumber: 'CASE-2026-001',
  title: 'Organizational Security Compliance Report',
  category: 'LEGITIMATE',
  description: 'Verified automated monthly compliance audit dispatched from authentic Google Workspace infrastructure with strict SPF, DKIM, and DMARC passing.',
  analyst: 'Lead SOC Analyst',
  rawEmail: `Delivered-To: analyst@cyberdefense.org
Received: by 2002:a05:6808:1545:b0:3c9:9999 with SMTP id x21csp1841443oie;
        Fri, 04 Sep 2026 14:15:32 -0700 (PDT)
X-Received: by 2002:a17:907:8f0c:b0:a28:6666 with SMTP id h12-20020a1709078f0c00b00a286666mr49282710gjw.12.1693862132100;
        Fri, 04 Sep 2026 14:15:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693862132; cv=none; d=google.com; s=arc-20240605;
        b=N7b92L...
Received: from mail-pj1-f41.google.com (mail-pj1-f41.google.com. [209.85.220.41])
        by mx.cyberdefense.org with ESMTPS id j18si2891152plm.391.2026.09.04.14.15.31
        for <analyst@cyberdefense.org>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Sep 2026 14:15:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3j4x@google.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
Authentication-Results: mx.cyberdefense.org;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V7b3kA;
       spf=pass (google.com: domain of 3j4x@google.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=3j4x@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=google.com; s=20230601; t=1693862130; x=1694466930;
        h=to:subject:message-id:date:from:mime-version:content-transfer-encoding;
        bh=yNf02kL4x8+V...;
        b=V7b3kAL9x2...
From: "Google Workspace Security" <workspace-alerts@google.com>
To: "SOC Analyst" <analyst@cyberdefense.org>
Subject: Google Workspace Monthly Security & Compliance Digest: August 2026
Date: Fri, 04 Sep 2026 21:15:28 +0000
Message-ID: <000000000000abcdef-workspace-sec@google.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="===============7829104829104829104=="

--===============7829104829104829104==
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 7bit

Dear Security Administrator,

This is your monthly automated security and compliance summary for your enterprise Google Workspace tenant (Domain: cyberdefense.org).

Summary of Audit Parameters (August 1 - August 31, 2026):
- 2-Step Verification (2SV) Corporate Enforcement: 100% compliant across 420 active identities.
- External Shared Drive Sharing Policy: 0 unauthorized external public link exposures detected.
- Suspicious Login Anomalies: 2 attempted brute-force sign-ins intercepted by adaptive risk evaluation.
- Mail Routing Integrity: SPF, DKIM, and DMARC enforcement active with p=reject policy.

You can inspect the full cryptographic audit log and export signed compliance certificates directly in your Google Workspace Admin console:
https://admin.google.com/ac/security/compliance

If you did not request or do not manage security for this organization, please contact your administrative team.

Best regards,
Google Workspace Cloud Security & Compliance Operations
1600 Amphitheatre Parkway, Mountain View, CA 94043, USA

--===============7829104829104829104==
Content-Type: application/pdf; name="workspace_compliance_august_2026.pdf"
Content-Disposition: attachment; filename="workspace_compliance_august_2026.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcTl8uXrp/Og0MTGCjQgMCBvYmoKPDwgL0xlbmd0aCA1IDAgUiAvRmlsdGVyIC9G
bGF0ZURlY29kZSA+PgpzdHJlYW0KeAEr5HIKWTAwMzU1UDBQMDMzNVUwM1dQUDAzNzVVUDBQMzVU
...
endstream
endobj
--===============7829104829104829104==--`,
};

export const DEMO_CASE_2_BEC: RawDemoCase = {
  caseId: 'CASE-2026-002',
  caseNumber: 'CASE-2026-002',
  title: 'Executive Impersonation Wire Transfer Diversion',
  category: 'BUSINESS_EMAIL_COMPROMISE',
  description: 'Targeted Business Email Compromise (BEC) attack impersonating the Chief Financial Officer. Features display name deception, Reply-To header divergence to a disposable webmail address, and urgent routing instructions to divert corporate vendor settlement funds.',
  analyst: 'Lead SOC Analyst',
  rawEmail: `Delivered-To: accounts.payable@corporate-energy.com
Received: from mx.corporate-energy.com (mx1.corporate-energy.com [10.20.1.5])
        by mail-internal.corporate-energy.com with ESMTP id p491028192;
        Fri, 04 Sep 2026 11:22:45 -0400
Received: from mta.offshore-transit.net (mta.offshore-transit.net [197.210.64.12])
        by mx.corporate-energy.com with ESMTPS id v8829102839
        for <accounts.payable@corporate-energy.com>;
        Fri, 04 Sep 2026 11:22:44 -0400
Received: from [197.210.64.12] (helo=desktop-accounting-win11.local)
        by mta.offshore-transit.net with esmtpa (Exim 4.94)
        id 1qJ83f-0004eR-7z; Fri, 04 Sep 2026 15:22:40 +0000
Received-SPF: fail (corporate-energy.com: 197.210.64.12 is not allowed in DNS SPF records) client-ip=197.210.64.12;
Authentication-Results: mx.corporate-energy.com;
       spf=fail (corporate-energy.com: 197.210.64.12 is unauthorized sending MTA) smtp.mailfrom=robert.vance@corporate-energy.com;
       dkim=fail (no signature present);
       dmarc=fail (p=quarantine dis=none) header.from=corporate-energy.com
From: "Robert Vance, CFO" <robert.vance@corporate-energy.com>
Reply-To: "Robert Vance (Executive Financial Desk)" <rvance.settlement.desk@gmail.com>
Return-Path: <bounce-daemon@offshore-transit.net>
To: "Accounts Payable Senior Analyst" <accounts.payable@corporate-energy.com>
Subject: URGENT: Revised Banking Remittance for Project Apollo Q3 Vendor Settlement ($482,500.00)
Date: Fri, 04 Sep 2026 11:22:38 -0400
Message-ID: <20260904112238.99281.qmail@mta.offshore-transit.net>
X-Mailer: Microsoft Outlook 16.0 (Forged Client)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi Team,

I am currently locked in confidential board acquisitions meetings until late afternoon and will not have direct phone access.

Our primary European contractor for the Project Apollo turbine installation has urgently updated their settlement depository accounts this morning due to an ongoing banking merger. 

The pending scheduled invoice of $482,500.00 USD must be settled prior to the 3:00 PM EST interbank clearing deadline today to prevent work stoppages on site. Do NOT transmit payment to the legacy Deutsche Bank account on file.

Please route the ACH/Wire settlement immediately to our updated temporary escrow beneficiary:
Beneficiary Name: Apex Maritime Global Logistics FZE
Bank Name: Standard Chartered Offshore Financial Unit
IBAN: AE890260001002938491023
SWIFT / BIC: SCBLAEADXXX
Reference: APOLLO-Q3-INV-99410-FINAL

Please execute this wire transfer as a priority release right away and email me the generated SWIFT MT103 confirmation slip to this thread as soon as completed. I will countersign the internal requisition voucher as soon as I exit the boardroom.

Regards,

Robert Vance
Chief Financial Officer & Executive Vice President
Corporate Energy Holdings Inc.
robert.vance@corporate-energy.com | Direct Mobile (SMS only during meetings): +1 (555) 019-2849`,
};

export const DEMO_CASE_3_PHISHING: RawDemoCase = {
  caseId: 'CASE-2026-003',
  caseNumber: 'CASE-2026-003',
  title: 'Spear-Phishing Credential Harvesting & Session Hijacking',
  category: 'CREDENTIAL_HARVESTING',
  description: 'Sophisticated Adversary-in-the-Middle (AiTM) spear-phishing lure masquerading as an urgent Microsoft 365 security alert. Employs Tor exit relay MTA transmission, typosquatted domain lookalikes, obfuscated redirect URLs, and weaponized macros.',
  analyst: 'Lead SOC Analyst',
  rawEmail: `Delivered-To: victim.staff@enterprise-network.io
Received: from mx.enterprise-network.io (mx.enterprise-network.io [172.16.0.4])
        by mailstore.enterprise-network.io with ESMTP id m389102812;
        Fri, 04 Sep 2026 09:41:12 -0700
Received: from exit-tor-node.zwiebelfreunde.de (exit-tor-node.zwiebelfreunde.de [185.220.101.5])
        by mx.enterprise-network.io with ESMTPS id q8192038102
        for <victim.staff@enterprise-network.io>;
        Fri, 04 Sep 2026 09:41:10 -0700
Received: from auth-srv.login-micros0ft-online.com ([194.165.16.88])
        by exit-tor-node.zwiebelfreunde.de with ESMTP id 98124412;
        Fri, 04 Sep 2026 16:41:05 +0000
Received-SPF: fail (microsoft.com: domain designates 185.220.101.5 as unauthorized sender) client-ip=185.220.101.5;
Authentication-Results: mx.enterprise-network.io;
       spf=fail (microsoft.com: domain specifies unauthorized sender 185.220.101.5) smtp.mailfrom=notification@login-micros0ft-online.com;
       dkim=fail (body hash did not verify);
       dmarc=fail (p=reject dis=reject) header.from=microsoft.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=login-micros0ft-online.com; s=k1; t=1693845665;
        h=from:to:subject:date:message-id;
        bh=InvalidHashValueFakePayload123456=;
        b=BrokenSignature...
From: "Microsoft 365 Security Center" <security-noreply@microsoft.com>
Reply-To: "Security Threat Assessment Unit" <sec-review@login-micros0ft-online.com>
Return-Path: <notice@login-micros0ft-online.com>
To: "Employee User" <victim.staff@enterprise-network.io>
Subject: ACTION REQUIRED: Multi-Factor Authentication Session Expired [Incident #M365-9821]
Date: Fri, 04 Sep 2026 16:41:01 +0000
Message-ID: <20260904164101.9912.auth@login-micros0ft-online.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_NextPart_000_001D_01D9D99A.4A981200"

------=_NextPart_000_001D_01D9D99A.4A981200
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: 7bit

<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="border-bottom: 2px solid #0078d4; padding-bottom: 12px; margin-bottom: 20px;">
    <h2 style="color: #0078d4; margin: 0;">Microsoft 365 Security Alert</h2>
    <p style="color: #666; font-size: 13px; margin: 4px 0 0 0;">Tenant Security Incident #M365-9821</p>
  </div>
  
  <p><strong>Immediate Action Required for user: victim.staff@enterprise-network.io</strong></p>
  
  <p>Our automated tenant telemetry detected an unauthorized sign-in attempt from an unrecognized IP location (IP: 194.165.16.88, Location: Moscow Oblast, RU). Consequently, your corporate session security token has been revoked to prevent account takeover.</p>
  
  <div style="background-color: #fff4ce; border-left: 4px solid #ffb900; padding: 12px; margin: 16px 0;">
    <p style="margin: 0; font-size: 14px; font-weight: bold; color: #333;">Session Termination Warning:</p>
    <p style="margin: 4px 0 0 0; font-size: 13px;">If you do not reverify your identity within 24 hours, your enterprise access to Outlook, Teams, and OneDrive will be automatically suspended by your organization's IT policy.</p>
  </div>
  
  <div style="text-align: center; margin: 30px 0;">
    <a href="https://login-micros0ft-online.com/auth/portal-verify/session?usr=victim.staff@enterprise-network.io&token=99fa8102" 
       style="background-color: #0078d4; color: #ffffff; padding: 14px 28px; text-decoration: none; border-radius: 4px; font-weight: bold; display: inline-block;">
      Reverify Microsoft 365 Credentials
    </a>
  </div>
  
  <p style="font-size: 12px; color: #888;">
    Alternative fallback verification endpoint: <br/>
    <code>https://auth-office365-verify.com/login/mfa-check?id=99412</code>
  </p>
  
  <hr style="border: 0; border-top: 1px solid #eee; margin: 24px 0;" />
  <p style="font-size: 11px; color: #999;">
    Microsoft Corporation, One Microsoft Way, Redmond, WA 98052 USA.<br/>
    This is an automated system notification. Replies to this email are forwarded to an unmonitored mailbox.
  </p>
</body>
</html>

------=_NextPart_000_001D_01D9D99A.4A981200
Content-Type: application/vnd.ms-excel.sheet.macroEnabled.12; name="Security_Audit_Log_M365.xlsm"
Content-Disposition: attachment; filename="Security_Audit_Log_M365.xlsm"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIAKV6ZFcAAAAAAAAAAAAAAAAGAAAAeGwvcmVscy93b3JraW5nLnhtbDw/eG1sIHZl
cnNpb249IjEuMCIgZW5jb2Rpbmc9IlVURi04IiBzdGFuZGFsb25lPSJ5ZXMiPz48UmVsYXRpb25z
...
------=_NextPart_000_001D_01D9D99A.4A981200--`,
};

export const ALL_DEMO_CASES: RawDemoCase[] = [
  DEMO_CASE_1_LEGITIMATE,
  DEMO_CASE_2_BEC,
  DEMO_CASE_3_PHISHING,
];
