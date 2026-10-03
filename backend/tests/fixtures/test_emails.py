"""
TraceMail Test Fixtures for Automated Testing & Benchmark Evaluation.
RFC 2606 compliant test domains (example.com, example.org, example.net).
"""

FIXTURE_LEGITIMATE_BUSINESS = b"""From: "Alice Harper" <alice.harper@example.com>
To: "Bob Smith" <bob.smith@example.org>
Subject: Q3 Financial Planning Meeting Agenda
Date: Mon, 15 Sep 2026 09:30:00 +0000
Message-ID: <legit-q3-20260915@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received: from mail.example.com (mail.example.com [198.51.100.10])
    by mx.example.org with ESMTP id ABC12345
    for <bob.smith@example.org>; Mon, 15 Sep 2026 09:30:05 +0000
Authentication-Results: mx.example.org;
    dkim=pass header.d=example.com header.s=202601;
    spf=pass (mx.example.org: domain of alice.harper@example.com designates 198.51.100.10 as permitted sender) smtp.mailfrom=alice.harper@example.com;
    dmarc=pass (p=REJECT sp=REJECT) header.from=example.com
Received-SPF: pass (mx.example.org: domain of alice.harper@example.com designates 198.51.100.10 as permitted sender)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=202601;
    h=from:to:subject:date:message-id:mime-version:content-type;
    bh=wO...=; b=xyz...==

Hi Bob,

Attached is our preliminary agenda for tomorrow's Q3 budget review. Please let me know if there are any specific line items from your team you would like added to the discussion.

Best regards,
Alice Harper
VP Finance, Example Corp
"""

FIXTURE_AUTHENTICATED_BEC = b"""From: "CEO John Doe" <ceo@example.com>
Reply-To: "Executive Office" <john.doe.exec2026@gmail.com>
To: "Finance Team" <finance@example.org>
Subject: URGENT: Confidential Wire Transfer Request - Acquisition Remittance
Date: Mon, 15 Sep 2026 14:15:00 +0000
Message-ID: <bec-urgent-20260915@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received: from outbound.mailprovider.com (outbound.mailprovider.com [203.0.113.50])
    by mx.example.org with ESMTP id BEC98765
    for <finance@example.org>; Mon, 15 Sep 2026 14:15:04 +0000
Authentication-Results: mx.example.org;
    dkim=pass header.d=example.com header.s=corp;
    spf=pass (mx.example.org: domain of ceo@example.com designates 203.0.113.50 as permitted sender) smtp.mailfrom=ceo@example.com;
    dmarc=pass (p=NONE) header.from=example.com
Received-SPF: pass

Team,

I am currently in an urgent confidential meeting and cannot take phone calls. 
We need to finalize the supplier acquisition payment due today. Please update payment details and execute an immediate wire transfer of $74,500 to our new bank account routing number.

Do not call my mobile. Reply to this email immediately with the wire transfer confirmation receipt.

Strictly confidential.

John Doe
Chief Executive Officer
"""

FIXTURE_CREDENTIAL_PHISHING = b"""From: "IT Security Helpdesk" <support@it-security-portal-login.xyz>
To: "Employee" <employee@example.org>
Subject: Action Required: Your Corporate Password Expires In 2 Hours
Date: Mon, 15 Sep 2026 11:00:00 +0000
Message-ID: <phish-sec-20260915@it-security-portal-login.xyz>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"
Received: from vps-nl-185.hostprovider.nl (vps-nl-185.hostprovider.nl [185.220.101.5])
    by mx.example.org with ESMTP id PHS11223
    for <employee@example.org>; Mon, 15 Sep 2026 11:00:02 +0000
Authentication-Results: mx.example.org;
    spf=fail (mx.example.org: domain of support@it-security-portal-login.xyz does not designate 185.220.101.5 as permitted sender);
    dmarc=fail (p=NONE) header.from=it-security-portal-login.xyz
Received-SPF: fail

<html>
<body>
<p>Dear Employee,</p>
<p>Your mailbox storage has exceeded 98% capacity and your corporate password expires today.</p>
<p><a href="http://login.microsoft.corporate-security-verify.top/auth/login?user=employee@example.org">Click here to verify your account and keep your existing password</a></p>
<p>Failure to login will result in immediate mailbox suspension.</p>
<p>IT Security Operations Center</p>
</body>
</html>
"""

FIXTURE_EXECUTIVE_IMPERSONATION = b"""From: "Director Sarah Jenkins <sarah.jenkins@example.com>" <attacker-sarah-jenkins@freemail-spoof.net>
Reply-To: "Sarah Jenkins" <sarah.jenkins.direct2026@gmail.com>
To: "Accounting Department" <accounting@example.org>
Subject: Quick assistance with employee gift cards
Date: Mon, 15 Sep 2026 16:45:00 +0000
Message-ID: <spoof-exec-20260915@freemail-spoof.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received: from relay.freemail-spoof.net (relay.freemail-spoof.net [194.26.29.11])
    by mx.example.org with ESMTP id SPF44556
    for <accounting@example.org>; Mon, 15 Sep 2026 16:45:05 +0000
Authentication-Results: mx.example.org;
    spf=softfail;
    dmarc=fail header.from=freemail-spoof.net
Received-SPF: softfail

Hi Accounting,

Are you at your desk right now? I need you to purchase some Apple gift cards for our client presentation by end of day. 
Please scratch the back, take clear photos, and send the codes directly to my personal email.

Handle this discreetly as it is a surprise for the executive team.

Sarah Jenkins
Managing Director
"""
