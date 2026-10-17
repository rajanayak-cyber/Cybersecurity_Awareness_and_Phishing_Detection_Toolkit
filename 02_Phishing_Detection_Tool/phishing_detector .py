import re
from urllib.parse import urlparse


def analyze_email(email_text):
    score = 0
    reasons = []
    text = email_text.lower()

    # 1. Urgent language
    urgent_words = [
        "urgent",
        "immediately",
        "action required",
        "deadline"
    ]

    found_urgent = [word for word in urgent_words if word in text]

    if found_urgent:
        score += 1
        reasons.append(
            "Urgent language detected: " + ", ".join(found_urgent)
        )

    # 2. Account warning
    account_warnings = [
        "unusual activity",
        "account suspended",
        "suspension"
    ]

    found_account_warnings = [
        word for word in account_warnings if word in text
    ]

    if found_account_warnings:
        score += 1
        reasons.append(
            "Account warning detected: "
            + ", ".join(found_account_warnings)
        )

    # 3. Credential request
    credential_words = [
        "login details",
        "password",
        "otp",
        "pin",
        "verification code"
    ]

    found_credentials = [
        word for word in credential_words if word in text
    ]

    if found_credentials:
        score += 2
        reasons.append(
            "Credential-related request detected: "
            + ", ".join(found_credentials)
        )

    # 4. Suspicious verification/action request
    verification_words = [
        "verify your account",
        "verification instructions",
        "click the link"
    ]

    found_verification = [
        word for word in verification_words if word in text
    ]

    if found_verification:
        score += 1
        reasons.append(
            "Suspicious verification/action request detected."
        )

    # 5. Suspicious activity
    suspicious_activity = [
        "suspicious activity",
        "flagged"
    ]

    found_suspicious = [
        word for word in suspicious_activity if word in text
    ]

    if found_suspicious:
        score += 1
        reasons.append(
            "Suspicious activity indicator detected."
        )

    # 6. Sensitive information
    sensitive_words = [
        "bank details",
        "card number",
        "payment information",
        "personal information"
    ]

    found_sensitive = [
        word for word in sensitive_words if word in text
    ]

    if found_sensitive:
        score += 2
        reasons.append(
            "Sensitive information request detected: "
            + ", ".join(found_sensitive)
        )

    # 7. URL check
    urls = re.findall(r'https?://[^\s]+', email_text)

    for url in urls:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if parsed.scheme.lower() != "https":
            score += 1
            reasons.append(
                "A URL in the message is not using HTTPS."
            )

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            score += 3
            reasons.append(
                "A URL uses an IP address instead of a domain name."
            )

        if "@" in url:
            score += 3
            reasons.append(
                "A URL contains '@', which may hide the real destination."
            )

    # Risk classification
    if score >= 6:
        risk = "HIGH RISK"
    elif score >= 3:
        risk = "MEDIUM RISK"
    else:
        risk = "LOW RISK"

    return risk, score, reasons


def main():
    print("=" * 60)
    print("       CYBERSECURITY PHISHING DETECTION TOOL")
    print("=" * 60)

    print("\nPaste the sample email text below.")
    print("Type END on a new line when finished.")
    print("Type EXIT to close the tool.\n")

    while True:
        lines = []

        while True:
            line = input()

            if line.strip().lower() == "exit":
                print("\nTool closed safely.")
                return

            if line.strip().upper() == "END":
                break

            lines.append(line)

        email_text = "\n".join(lines).strip()

        if not email_text:
            print("\nPlease enter some email text.\n")
            continue

        risk, score, reasons = analyze_email(email_text)

        print("\n" + "-" * 60)
        print("PHISHING ANALYSIS RESULT")
        print("-" * 60)
        print(f"Risk Score: {score}")
        print(f"Risk Level: {risk}")

        if reasons:
            print("\nIndicators detected:")
            for reason in reasons:
                print(f"- {reason}")
        else:
            print("\nNo obvious phishing indicators detected.")

        print("\nSafety Recommendation:")

        if risk == "HIGH RISK":
            print("Do not click links, open attachments, or provide sensitive information.")
        elif risk == "MEDIUM RISK":
            print("Verify the sender and message details before taking any action.")
        else:
            print("No obvious phishing indicators were detected, but remain cautious.")

        print("-" * 60)
        print("Note: This tool uses basic heuristic checks.")
        print("It is intended for educational and awareness purposes.")
        print("-" * 60 + "\n")


if __name__ == "__main__":
    main()