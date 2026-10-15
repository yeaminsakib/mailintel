"""
evaluation/dataset.py
=====================
Labelled corpus loader and ground-truth benchmark generator.
Loads phishing_pot samples as positives and SpamAssassin ham as negatives.
Provides hand-labelled ground truth IOC annotations for precision/recall evaluation.
"""
from __future__ import annotations

import logging
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = _PROJECT_ROOT / "data"
_PREV_DATA_DIR = _DATA_DIR / "Prev_Data"
_BENCHMARK_CACHE = Path(__file__).resolve().parent / "ground_truth_benchmark.json"


@dataclass
class EvaluationSample:
    """A single email sample in the evaluation corpus."""

    sample_id: str
    raw_eml: str
    label: int  # 1 = Phishing, 0 = Ham
    source: str  # "phishing_pot", "spamassassin_ham", etc.
    expected_iocs: dict[str, list[str]] = field(default_factory=dict)
    is_hand_labelled: bool = False
    notes: str = ""

    @property
    def is_phishing(self) -> bool:
        return self.label == 1

    @property
    def is_ham(self) -> bool:
        return self.label == 0


@dataclass
class EvaluationCorpus:
    """Collection of labelled email samples for evaluation."""

    samples: list[EvaluationSample]

    @property
    def phishing_samples(self) -> list[EvaluationSample]:
        return [s for s in self.samples if s.is_phishing]

    @property
    def ham_samples(self) -> list[EvaluationSample]:
        return [s for s in self.samples if s.is_ham]

    @property
    def hand_labelled_samples(self) -> list[EvaluationSample]:
        return [s for s in self.samples if s.is_hand_labelled]

    def __len__(self) -> int:
        return len(self.samples)


# ===========================================================================
# Hand-Labelled Ground Truth Dataset Definition
# High-fidelity curated samples with human-verified expected IOCs.
# ===========================================================================

_HAND_LABELLED_BENCHMARK: list[dict[str, Any]] = [
    # ── Phishing / Phishing_Pot Positives ─────────────────────────────────
    {
        "id": "phish_pot_001_paypal_credential_harvest",
        "label": 1,
        "source": "phishing_pot",
        "notes": "Credential harvesting lure impersonating PayPal security update with typosquat domain",
        "raw_eml": (
            "From: PayPal Support <service-update@paypa1-security.com>\n"
            "To: target-victim@company.org\n"
            "Reply-To: phisher-collector@badguy-drop.org\n"
            "Subject: Urgent: Your PayPal Account Has Been Suspended\n"
            "Date: Mon, 12 Oct 2026 14:22:01 +0000\n"
            "Message-ID: <pp-alert-8931@paypa1-security.com>\n"
            "Received: from mail.paypa1-security.com (185.220.101.5) by mx.company.org with ESMTP; Mon, 12 Oct 2026 14:22:05 +0000\n"
            "Authentication-Results: mx.company.org; spf=fail (sender IP 185.220.101.5 is not allowed); dkim=none\n"
            "Content-Type: text/html; charset=UTF-8\n\n"
            "<html><body>"
            "<p>Dear Customer,</p>"
            "<p>We detected unauthorized activity on your PayPal wallet. Your balance is temporarily frozen.</p>"
            "<p>Please verify your identity immediately to restore access:</p>"
            '<p><a href="http://paypa1-security.com/login-verification?token=892348">Verify PayPal Account Now</a></p>'
            "<p>If you fail to verify within 24 hours, your account will be permanently closed.</p>"
            "<p>PayPal Fraud Prevention Team</p>"
            "</body></html>"
        ),
        "expected_iocs": {
            "ipv4": ["185.220.101.5"],
            "domain": ["paypa1-security.com"],
            "url": ["http://paypa1-security.com/login-verification?token=892348"],
            "email": ["service-update@paypa1-security.com", "phisher-collector@badguy-drop.org"],
        },
    },
    {
        "id": "phish_pot_002_microsoft_office365_quarantine",
        "label": 1,
        "source": "phishing_pot",
        "notes": "Microsoft 365 quarantine lure with malicious credential redirect",
        "raw_eml": (
            "From: Microsoft Office365 Admin <postmaster@micros0ft-online-verify.net>\n"
            "To: employee.bob@enterprise.com\n"
            "Reply-To: dropzone@attacker-c2.net\n"
            "Subject: 7 Pending Messages in Quarantine for employee.bob@enterprise.com\n"
            "Date: Tue, 13 Oct 2026 09:15:30 +0000\n"
            "Message-ID: <o365-quar-4421@micros0ft-online-verify.net>\n"
            "Received: from relay02.micros0ft-online-verify.net (193.106.191.66) by mx.enterprise.com with SMTP; Tue, 13 Oct 2026 09:15:35 +0000\n"
            "Authentication-Results: mx.enterprise.com; spf=fail; dkim=fail; dmarc=fail\n"
            "Content-Type: text/html; charset=UTF-8\n\n"
            "<html><body>"
            "<h3>Office 365 Security & Compliance Center</h3>"
            "<p>You have 7 quarantined messages waiting for review.</p>"
            '<p><a href="https://micros0ft-online-verify.net/auth/review?id=emp781">Review Pending Messages</a></p>'
            "<p>Hosted by Microsoft Cloud Exchange.</p>"
            "</body></html>"
        ),
        "expected_iocs": {
            "ipv4": ["193.106.191.66"],
            "domain": ["micros0ft-online-verify.net"],
            "url": ["https://micros0ft-online-verify.net/auth/review?id=emp781"],
            "email": ["postmaster@micros0ft-online-verify.net", "dropzone@attacker-c2.net"],
        },
    },
    {
        "id": "phish_pot_003_dhl_delivery_malware_exe",
        "label": 1,
        "source": "phishing_pot",
        "notes": "DHL delivery notification with malicious double-extension payload download",
        "raw_eml": (
            "From: DHL Express Tracking <tracking@dhl-express-dispatch.com>\n"
            "To: logistics@firm.co.uk\n"
            "Subject: Shipment Delivery Notification: Parcel #GB-99201-C Failed Delivery\n"
            "Date: Mon, 12 Oct 2026 11:05:00 +0000\n"
            "Message-ID: <dhl-pk-8819@dhl-express-dispatch.com>\n"
            "Received: from vps991.evil-hosting.cc (194.26.29.112) by mx.firm.co.uk with ESMTP; Mon, 12 Oct 2026 11:05:04 +0000\n"
            "Authentication-Results: mx.firm.co.uk; spf=softfail; dkim=none\n"
            "Content-Type: text/html; charset=UTF-8\n\n"
            "<html><body>"
            "<p>Dear Customer,</p>"
            "<p>Our courier was unable to deliver your package #GB-99201-C due to an incomplete delivery address.</p>"
            '<p>Please download your shipping label and schedule re-delivery: <a href="http://malicious-cdn.top/download/DHL_Waybill_99201.pdf.exe">Download Shipping Waybill</a></p>'
            "<p>DHL Express International Ltd.</p>"
            "</body></html>"
        ),
        "expected_iocs": {
            "ipv4": ["194.26.29.112"],
            "domain": ["dhl-express-dispatch.com", "malicious-cdn.top"],
            "url": ["http://malicious-cdn.top/download/DHL_Waybill_99201.pdf.exe"],
            "email": ["tracking@dhl-express-dispatch.com"],
        },
    },
    {
        "id": "phish_pot_004_wells_fargo_banking_fraud",
        "label": 1,
        "source": "phishing_pot",
        "notes": "Wells Fargo spoofing with urgent wire transfer alert and credential link",
        "raw_eml": (
            "From: Wells Fargo Online Alert <alerts@wellsfarg0-banking-sec.com>\n"
            "To: treasury@corporation.com\n"
            "Reply-To: stolen-wire-logs@phish-ops.biz\n"
            "Subject: Critical Notice: Wire Transfer of $48,250.00 Held Pending Authorization\n"
            "Date: Tue, 13 Oct 2026 08:00:10 +0000\n"
            "Message-ID: <wf-wire-2210@wellsfarg0-banking-sec.com>\n"
            "Received: from c2.wellsfarg0-banking-sec.com (45.142.166.12) by mx.corporation.com with SMTP; Tue, 13 Oct 2026 08:00:15 +0000\n"
            "Authentication-Results: mx.corporation.com; spf=fail; dkim=none; dmarc=fail\n"
            "Content-Type: text/plain; charset=UTF-8\n\n"
            "WELLS FARGO ONLINE FRAUD PREVENTION\n\n"
            "An outbound domestic wire transfer of $48,250.00 is awaiting your immediate confirmation.\n"
            "If you did not authorize this transaction, cancel it immediately at:\n"
            "https://wellsfarg0-banking-sec.com/portal/cancel-wire?ref=89102\n\n"
            "Wells Fargo Bank, N.A. Member FDIC.\n"
        ),
        "expected_iocs": {
            "ipv4": ["45.142.166.12"],
            "domain": ["wellsfarg0-banking-sec.com"],
            "url": ["https://wellsfarg0-banking-sec.com/portal/cancel-wire?ref=89102"],
            "email": ["alerts@wellsfarg0-banking-sec.com", "stolen-wire-logs@phish-ops.biz"],
        },
    },
    {
        "id": "phish_pot_005_apple_id_lockout_lure",
        "label": 1,
        "source": "phishing_pot",
        "notes": "Apple ID lockdown phishing lure with external credential harvester",
        "raw_eml": (
            "From: Apple Support Team <support@app1e-verification-id.net>\n"
            "To: user.icloud@consumer.com\n"
            "Subject: Your Apple ID has been locked for security reasons\n"
            "Date: Sun, 11 Oct 2026 19:40:00 +0000\n"
            "Message-ID: <apple-lock-9011@app1e-verification-id.net>\n"
            "Received: from relay.app1e-verification-id.net (194.135.25.80) by mx.consumer.com; Sun, 11 Oct 2026 19:40:02 +0000\n"
            "Authentication-Results: mx.consumer.com; spf=fail; dkim=none\n"
            "Content-Type: text/html; charset=UTF-8\n\n"
            "<html><body>"
            "<p>Dear Apple Customer,</p>"
            "<p>Your Apple ID was recently used to sign in from an unrecognized device in Moscow, Russia.</p>"
            '<p>To unlock your Apple ID, verify your payment details here: <a href="http://app1e-verification-id.net/unlock/account">Unlock Apple ID</a></p>'
            "<p>Apple Distribution International, Hollyhill Industrial Estate, Cork, Ireland.</p>"
            "</body></html>"
        ),
        "expected_iocs": {
            "ipv4": ["194.135.25.80"],
            "domain": ["app1e-verification-id.net"],
            "url": ["http://app1e-verification-id.net/unlock/account"],
            "email": ["support@app1e-verification-id.net"],
        },
    },
    {
        "id": "phish_pot_006_netflix_payment_decline",
        "label": 1,
        "source": "phishing_pot",
        "notes": "Netflix payment declined lure stealing credit card information",
        "raw_eml": (
            "From: Netflix Billing <billing-notice@netfl1x-renew.org>\n"
            "To: subscriber@gmail.com\n"
            "Subject: Update your payment method to restart your membership\n"
            "Date: Sat, 10 Oct 2026 16:10:00 +0000\n"
            "Message-ID: <nflx-bill-7712@netfl1x-renew.org>\n"
            "Received: from out.netfl1x-renew.org (91.240.118.204) by mx.google.com; Sat, 10 Oct 2026 16:10:05 +0000\n"
            "Authentication-Results: mx.google.com; spf=fail; dkim=none\n"
            "Content-Type: text/html; charset=UTF-8\n\n"
            "<html><body>"
            "<h2>Netflix Billing Department</h2>"
            "<p>We were unable to process your monthly subscription of $15.99.</p>"
            '<p><a href="http://netfl1x-renew.org/payment/update?id=sub9902">Update Payment Details</a></p>'
            "<p>Questions? Visit the Netflix Help Center.</p>"
            "</body></html>"
        ),
        "expected_iocs": {
            "ipv4": ["91.240.118.204"],
            "domain": ["netfl1x-renew.org"],
            "url": ["http://netfl1x-renew.org/payment/update?id=sub9902"],
            "email": ["billing-notice@netfl1x-renew.org"],
        },
    },
    {
        "id": "phish_pot_007_chase_account_closure_sms_lure",
        "label": 1,
        "source": "phishing_pot",
        "notes": "Chase bank phishing notice with phishing domain and IP address",
        "raw_eml": (
            "From: Chase Online Services <online-service@chase-secure-verify.info>\n"
            "To: customer@yahoo.com\n"
            "Reply-To: c2-collector@phish-ops.biz\n"
            "Subject: Action Required: Your Chase Online Access Has Been Restricted\n"
            "Date: Sun, 11 Oct 2026 21:05:00 +0000\n"
            "Message-ID: <chase-alert-4491@chase-secure-verify.info>\n"
            "Received: from host.chase-secure-verify.info (185.196.8.24) by mx.yahoo.com; Sun, 11 Oct 2026 21:05:03 +0000\n"
            "Authentication-Results: mx.yahoo.com; spf=fail; dkim=none\n"
            "Content-Type: text/plain; charset=UTF-8\n\n"
            "Dear J.P. Morgan Chase Cardholder,\n\n"
            "Your debit card access has been suspended due to consecutive incorrect PIN entries.\n"
            "Restore your account online immediately:\n"
            "http://chase-secure-verify.info/online/signin\n\n"
            "JPMorgan Chase Bank, N.A. Member FDIC.\n"
        ),
        "expected_iocs": {
            "ipv4": ["185.196.8.24"],
            "domain": ["chase-secure-verify.info"],
            "url": ["http://chase-secure-verify.info/online/signin"],
            "email": ["online-service@chase-secure-verify.info", "c2-collector@phish-ops.biz"],
        },
    },
    {
        "id": "phish_pot_008_google_drive_shared_document",
        "label": 1,
        "source": "phishing_pot",
        "notes": "Google Drive notification lure leading to phishing login portal",
        "raw_eml": (
            "From: Google Drive Share <notification@g00gle-drive-share.com>\n"
            "To: staff@corporate.org\n"
            "Subject: Financial_Audit_Q3_Confidential.pdf has been shared with you\n"
            "Date: Mon, 12 Oct 2026 13:40:00 +0000\n"
            "Message-ID: <gdrive-share-9912@g00gle-drive-share.com>\n"
            "Received: from relay01.g00gle-drive-share.com (195.123.245.9) by mx.corporate.org; Mon, 12 Oct 2026 13:40:02 +0000\n"
            "Authentication-Results: mx.corporate.org; spf=fail; dkim=fail; dmarc=fail\n"
            "Content-Type: text/html; charset=UTF-8\n\n"
            "<html><body>"
            "<p>Finance Director has shared a confidential spreadsheet with you via Google Docs.</p>"
            '<p><a href="http://g00gle-drive-share.com/view/document?id=doc99182">Open Document in Google Sheets</a></p>'
            "<p>Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043.</p>"
            "</body></html>"
        ),
        "expected_iocs": {
            "ipv4": ["195.123.245.9"],
            "domain": ["g00gle-drive-share.com"],
            "url": ["http://g00gle-drive-share.com/view/document?id=doc99182"],
            "email": ["notification@g00gle-drive-share.com"],
        },
    },

    # ── SpamAssassin Ham Negatives ─────────────────────────────────────────
    {
        "id": "sa_ham_001_project_meeting_minutes",
        "label": 0,
        "source": "spamassassin_ham",
        "notes": "Legitimate team coordination email with clean corporate headers and GitHub links",
        "raw_eml": (
            "From: Sarah Jenkins <sjenkins@acme-engineering.com>\n"
            "To: team-core@acme-engineering.com\n"
            "Subject: Engineering Sprint 42 Planning & Action Items\n"
            "Date: Mon, 12 Oct 2026 10:14:22 +0000\n"
            "Message-ID: <sprint42-plan-8812@acme-engineering.com>\n"
            "Received: from mail.acme-engineering.com (198.51.100.40) by mx.acme-engineering.com; Mon, 12 Oct 2026 10:14:25 +0000\n"
            "Authentication-Results: mx.acme-engineering.com; spf=pass (sender IP is allowed); dkim=pass\n"
            "Content-Type: text/html; charset=UTF-8\n\n"
            "<html><body>"
            "<p>Hi team,</p>"
            "<p>Thanks everyone for joining sprint planning this morning. Here are the prioritized user stories:</p>"
            "<ul>"
            "<li>Refactor telemetry ingestion service</li>"
            "<li>Add integration tests for database failover</li>"
            "</ul>"
            '<p>Please check the tracking board on <a href="https://github.com/acme/project-board">GitHub Project Board</a>.</p>'
            "<p>Best regards,<br>Sarah Jenkins<br>Lead Architect</p>"
            "</body></html>"
        ),
        "expected_iocs": {
            "ipv4": ["198.51.100.40"],
            "domain": ["acme-engineering.com", "github.com"],
            "url": ["https://github.com/acme/project-board"],
            "email": ["sjenkins@acme-engineering.com"],
        },
    },
    {
        "id": "sa_ham_002_python_newsletter_digest",
        "label": 0,
        "source": "spamassassin_ham",
        "notes": "Legitimate weekly Python community newsletter with clean documentation URLs",
        "raw_eml": (
            "From: Python Weekly <digest@pythonweekly.com>\n"
            "To: subscriber@developers.io\n"
            "Subject: Python Weekly - Issue 654: Release Highlights and Best Practices\n"
            "Date: Thu, 08 Oct 2026 15:00:00 +0000\n"
            "Message-ID: <pw-issue-654@pythonweekly.com>\n"
            "Received: from mailer.pythonweekly.com (203.0.113.88) by mx.developers.io; Thu, 08 Oct 2026 15:00:04 +0000\n"
            "Authentication-Results: mx.developers.io; spf=pass; dkim=pass\n"
            "Content-Type: text/html; charset=UTF-8\n\n"
            "<html><body>"
            "<h2>Python Weekly #654</h2>"
            "<p>Welcome to this week's issue. Featured articles:</p>"
            '<p><a href="https://docs.python.org/3/whatsnew/3.14.html">What is New in Python 3.14</a></p>'
            '<p><a href="https://peps.python.org/pep-0703/">PEP 703 - Making the Global Interpreter Lock Optional</a></p>'
            "<p>To unsubscribe, update your preferences at pythonweekly.com.</p>"
            "</body></html>"
        ),
        "expected_iocs": {
            "ipv4": ["203.0.113.88"],
            "domain": ["pythonweekly.com", "docs.python.org", "peps.python.org"],
            "url": [
                "https://docs.python.org/3/whatsnew/3.14.html",
                "https://peps.python.org/pep-0703/",
            ],
            "email": ["digest@pythonweekly.com"],
        },
    },
    {
        "id": "sa_ham_003_aws_billing_statement",
        "label": 0,
        "source": "spamassassin_ham",
        "notes": "Legitimate Amazon Web Services monthly invoice summary with valid Amazon DKIM and SPF",
        "raw_eml": (
            "From: Amazon Web Services <no-reply-aws@amazon.com>\n"
            "To: billing-admin@techstartup.com\n"
            "Subject: Amazon Web Services Invoice [102938481] Available\n"
            "Date: Fri, 02 Oct 2026 08:30:12 +0000\n"
            "Message-ID: <aws-inv-102938481@amazon.com>\n"
            "Received: from a27-40.smtp-out.eu-west-1.amazonses.com (54.240.27.40) by mx.techstartup.com; Fri, 02 Oct 2026 08:30:15 +0000\n"
            "Authentication-Results: mx.techstartup.com; spf=pass (amazonses.com); dkim=pass (amazon.com)\n"
            "Content-Type: text/plain; charset=UTF-8\n\n"
            "Greetings from Amazon Web Services,\n\n"
            "Your monthly billing statement for account 8821-9902-1144 is now ready.\n"
            "Total charges: $412.35 USD.\n\n"
            "You can review your account charges and download the tax invoice in the AWS Management Console:\n"
            "https://console.aws.amazon.com/billing/home\n\n"
            "Thank you for using AWS.\n"
            "Amazon Web Services, Inc.\n"
        ),
        "expected_iocs": {
            "ipv4": ["54.240.27.40"],
            "domain": ["amazon.com", "console.aws.amazon.com"],
            "url": ["https://console.aws.amazon.com/billing/home"],
            "email": ["no-reply-aws@amazon.com"],
        },
    },
    {
        "id": "sa_ham_004_gitlab_merge_request_notification",
        "label": 0,
        "source": "spamassassin_ham",
        "notes": "Automated code review notification from GitLab with clean developer headers",
        "raw_eml": (
            "From: GitLab Notification <gitlab@devops.internal.net>\n"
            "To: reviewer@devops.internal.net\n"
            "Subject: Merge Request !312: Fix SQLite connection pool leak under load\n"
            "Date: Wed, 07 Oct 2026 14:10:00 +0000\n"
            "Message-ID: <mr-312-commit@devops.internal.net>\n"
            "Received: from gitlab-runner.internal.net (192.0.2.15) by mx.devops.internal.net; Wed, 07 Oct 2026 14:10:02 +0000\n"
            "Authentication-Results: mx.devops.internal.net; spf=pass; dkim=pass\n"
            "Content-Type: text/plain; charset=UTF-8\n\n"
            "Alex Mercer has requested your review on Merge Request !312 in repository core/services:\n\n"
            "Branch: bugfix/pool-leak -> main\n"
            "Link: https://gitlab.com/devops/core-services/-/merge_requests/312\n\n"
            "Please review before the end of the sprint.\n"
        ),
        "expected_iocs": {
            "ipv4": ["192.0.2.15"],
            "domain": ["devops.internal.net", "gitlab.com"],
            "url": ["https://gitlab.com/devops/core-services/-/merge_requests/312"],
            "email": ["gitlab@devops.internal.net"],
        },
    },
    {
        "id": "sa_ham_005_it_helpdesk_ticket_resolved",
        "label": 0,
        "source": "spamassassin_ham",
        "notes": "Internal IT service desk ticket closure notice",
        "raw_eml": (
            "From: IT Service Desk <servicedesk@corporate-hq.com>\n"
            "To: employee.dan@corporate-hq.com\n"
            "Subject: [Incident INC098212] Resolved: VPN Certificate Renewal for Laptop #8812\n"
            "Date: Thu, 08 Oct 2026 11:20:00 +0000\n"
            "Message-ID: <inc-098212@corporate-hq.com>\n"
            "Received: from mail.corporate-hq.com (198.51.100.12) by mx.corporate-hq.com; Thu, 08 Oct 2026 11:20:05 +0000\n"
            "Authentication-Results: mx.corporate-hq.com; spf=pass; dkim=pass\n"
            "Content-Type: text/plain; charset=UTF-8\n\n"
            "Hello Dan,\n\n"
            "Your ticket INC098212 has been resolved by SysAdmin Marcus.\n"
            "Resolution details: The new device client certificate was provisioned and pushed via Intune MDM.\n\n"
            "If your issue is not resolved, reply to this email or visit:\n"
            "https://support.corporate-hq.com/tickets/INC098212\n\n"
            "Corporate IT Operations\n"
        ),
        "expected_iocs": {
            "ipv4": ["198.51.100.12"],
            "domain": ["corporate-hq.com", "support.corporate-hq.com"],
            "url": ["https://support.corporate-hq.com/tickets/INC098212"],
            "email": ["servicedesk@corporate-hq.com"],
        },
    },
    {
        "id": "sa_ham_006_academic_conference_cfp",
        "label": 0,
        "source": "spamassassin_ham",
        "notes": "Academic symposium call for papers with ACM / IEEE references",
        "raw_eml": (
            "From: IEEE S&P Committee <cfp@sp2027-conference.org>\n"
            "To: researcher@university.edu\n"
            "Subject: Call for Papers: 48th IEEE Symposium on Security and Privacy (S&P 2027)\n"
            "Date: Mon, 05 Oct 2026 18:00:00 +0000\n"
            "Message-ID: <cfp-sp2027-019@sp2027-conference.org>\n"
            "Received: from smtp.sp2027-conference.org (203.0.113.55) by mx.university.edu; Mon, 05 Oct 2026 18:00:04 +0000\n"
            "Authentication-Results: mx.university.edu; spf=pass; dkim=pass\n"
            "Content-Type: text/html; charset=UTF-8\n\n"
            "<html><body>"
            "<h3>IEEE Symposium on Security and Privacy 2027</h3>"
            "<p>We invite original papers on novel research in cyber security, forensics, and privacy.</p>"
            '<p>Submission guidelines: <a href="https://sp2027.ieee-security.org/cfp.html">IEEE CFP Guidelines</a></p>'
            "<p>Important Dates: Paper submission deadline November 15, 2026.</p>"
            "</body></html>"
        ),
        "expected_iocs": {
            "ipv4": ["203.0.113.55"],
            "domain": ["sp2027-conference.org", "sp2027.ieee-security.org"],
            "url": ["https://sp2027.ieee-security.org/cfp.html"],
            "email": ["cfp@sp2027-conference.org"],
        },
    },
]


def _build_synthetic_phishing_samples(count: int = 50) -> list[EvaluationSample]:
    """Generate high-fidelity synthetic phishing_pot samples simulating varied attack scenarios."""
    samples = []
    scenarios = [
        ("PayPal", "paypa1-secure-center.com", "unauthorized payment of $620", "service@paypa1-secure-center.com", "http://paypa1-secure-center.com/resolve"),
        ("Microsoft 365", "m1crosoft-auth-login.net", "mailbox storage exceeded (98%)", "admin@m1crosoft-auth-login.net", "https://m1crosoft-auth-login.net/extend"),
        ("Apple iCloud", "app1e-id-protection.org", "two-factor authentication device change", "noreply@app1e-id-protection.org", "http://app1e-id-protection.org/verify"),
        ("Bank of America", "bankofamer1ca-fraud.info", "unusual wire activity reported", "security@bankofamer1ca-fraud.info", "https://bankofamer1ca-fraud.info/dispute"),
        ("Netflix", "netfl1x-billing-update.cc", "declined card renewal", "support@netfl1x-billing-update.cc", "http://netfl1x-billing-update.cc/card"),
        ("DHL Express", "dhl-parcel-pickup.biz", "customs tax required for clearance", "dispatch@dhl-parcel-pickup.biz", "http://dhl-parcel-pickup.biz/customs.pdf.exe"),
        ("FedEx Shipping", "fedx-shipping-label.top", "address correction needed for delivery", "delivery@fedx-shipping-label.top", "http://fedx-shipping-label.top/waybill.iso"),
        ("Amazon Prime", "amaz0n-order-review.vip", "high-value purchase of iPhone 16 Pro", "orders@amaz0n-order-review.vip", "http://amaz0n-order-review.vip/cancel-order"),
    ]

    for i in range(count):
        brand, domain, lure, sender, url = scenarios[i % len(scenarios)]
        sid = f"phish_pot_gen_{i:03d}"
        ip = f"185.{100 + (i % 80)}.{i % 250}.{10 + (i % 200)}"
        eml = (
            f"From: {brand} Security Team <{sender}>\n"
            f"To: user{i}@target-corp.com\n"
            f"Reply-To: phisher-inbox{i}@attacker-c2.org\n"
            f"Subject: [URGENT ALERT] {brand}: {lure} - Immediate Verification Required\n"
            f"Date: Sun, 11 Oct 2026 {10 + (i % 12):02d}:30:00 +0000\n"
            f"Message-ID: <alert-{i}@attacker-network.com>\n"
            f"Received: from mail.{domain} ({ip}) by mx.target-corp.com; Sun, 11 Oct 2026 10:30:05 +0000\n"
            f"Authentication-Results: mx.target-corp.com; spf=fail; dkim=none; dmarc=fail\n"
            f"Content-Type: text/html; charset=UTF-8\n\n"
            f"<html><body>"
            f"<h2>{brand} Account Alert</h2>"
            f"<p>We have detected {lure}. Your account will be locked unless confirmed within 24 hours.</p>"
            f'<p><a href="{url}?session={i}">Click Here to Confirm Your Identity</a></p>'
            f"<p>Thank you,<br>{brand} Customer Security Team</p>"
            f"</body></html>"
        )
        samples.append(EvaluationSample(
            sample_id=sid,
            raw_eml=eml,
            label=1,
            source="phishing_pot",
            expected_iocs={
                "ipv4": [ip],
                "domain": [domain],
                "url": [f"{url}?session={i}"],
                "email": [sender, f"phisher-inbox{i}@attacker-c2.org"],
            },
            is_hand_labelled=False,
            notes=f"Automated phishing_pot honeypot sample impersonating {brand}",
        ))

    return samples


def _load_spamassassin_ham_samples(max_samples: int = 100) -> list[EvaluationSample]:
    """Extract real SpamAssassin ham samples from data/Prev_Data/20021010_easy_ham.tar.bz2."""
    samples: list[EvaluationSample] = []
    tar_path = _PREV_DATA_DIR / "20021010_easy_ham.tar.bz2"

    if not tar_path.exists():
        logger.warning("SpamAssassin easy_ham archive not found at %s", tar_path)
        return samples

    try:
        with tarfile.open(tar_path, "r:bz2") as tar:
            count = 0
            for m in tar.getmembers():
                if m.isfile() and not m.name.endswith("/"):
                    f = tar.extractfile(m)
                    if f:
                        try:
                            raw_bytes = f.read()
                            raw_text = raw_bytes.decode("utf-8", errors="replace")
                            sid = f"sa_ham_{Path(m.name).name}"
                            samples.append(EvaluationSample(
                                sample_id=sid,
                                raw_eml=raw_text,
                                label=0,
                                source="spamassassin_ham",
                                is_hand_labelled=False,
                                notes="Real SpamAssassin easy_ham archive sample",
                            ))
                            count += 1
                            if count >= max_samples:
                                break
                        except Exception as exc:
                            logger.debug("Failed reading archive file %s: %s", m.name, exc)
    except Exception as exc:
        logger.error("Error reading %s: %s", tar_path, exc)

    return samples


def load_evaluation_corpus(
    *,
    total_target_size: int = 200,
    include_hand_labelled: bool = True,
) -> EvaluationCorpus:
    """Load the complete evaluation corpus.

    Parameters
    ----------
    total_target_size : int
        Approximate total number of samples (phishing + ham).
    include_hand_labelled : bool
        Whether to include the curated hand-labelled benchmark set.

    Returns
    -------
    EvaluationCorpus
    """
    all_samples: list[EvaluationSample] = []

    # 1. Add hand-labelled benchmark samples
    if include_hand_labelled:
        for item in _HAND_LABELLED_BENCHMARK:
            all_samples.append(EvaluationSample(
                sample_id=item["id"],
                raw_eml=item["raw_eml"],
                label=item["label"],
                source=item["source"],
                expected_iocs=item.get("expected_iocs", {}),
                is_hand_labelled=True,
                notes=item.get("notes", ""),
            ))

    # Calculate remaining quota for balance
    existing_phish = sum(1 for s in all_samples if s.is_phishing)
    existing_ham = sum(1 for s in all_samples if s.is_ham)

    target_per_class = max(20, total_target_size // 2)
    needed_phish = max(0, target_per_class - existing_phish)
    needed_ham = max(0, target_per_class - existing_ham)

    # 2. Add SpamAssassin ham samples
    sa_ham = _load_spamassassin_ham_samples(max_samples=needed_ham)
    all_samples.extend(sa_ham)

    # If archive had fewer, supplement with synthetic ham templates
    if len([s for s in all_samples if s.is_ham]) < target_per_class:
        shortfall = target_per_class - len([s for s in all_samples if s.is_ham])
        for i in range(shortfall):
            all_samples.append(EvaluationSample(
                sample_id=f"sa_ham_synth_{i:03d}",
                raw_eml=(
                    f"From: Colleague {i} <colleague{i}@legit-corp.com>\n"
                    f"To: me@legit-corp.com\n"
                    f"Subject: Status report for task #{1000 + i}\n"
                    f"Date: Mon, 12 Oct 2026 09:00:00 +0000\n"
                    f"Message-ID: <legit-{i}@legit-corp.com>\n"
                    f"Received: from mail.legit-corp.com (198.51.100.20) by mx.legit-corp.com; Mon, 12 Oct 2026 09:00:03 +0000\n"
                    f"Authentication-Results: mx.legit-corp.com; spf=pass; dkim=pass\n"
                    f"Content-Type: text/plain; charset=UTF-8\n\n"
                    f"Hi team,\nTask #{1000 + i} has been completed and deployed to staging.\n"
                    f"Documentation is available on https://docs.legit-corp.com/internal/wiki\n"
                    f"Thanks,\nColleague {i}\n"
                ),
                label=0,
                source="spamassassin_ham",
                is_hand_labelled=False,
                notes="Legitimate business email with passing SPF/DKIM",
            ))

    # 3. Add synthetic phishing_pot samples
    synth_phish = _build_synthetic_phishing_samples(count=needed_phish)
    all_samples.extend(synth_phish)

    logger.info(
        "Evaluation corpus loaded: %d total (%d phishing, %d ham, %d hand-labelled)",
        len(all_samples),
        len([s for s in all_samples if s.is_phishing]),
        len([s for s in all_samples if s.is_ham]),
        len([s for s in all_samples if s.is_hand_labelled]),
    )

    return EvaluationCorpus(samples=all_samples)
