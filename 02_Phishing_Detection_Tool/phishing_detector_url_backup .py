import re
from urllib.parse import urlparse


def check_url(url):
    score = 0
    reasons = []

    url = url.strip()

    # Basic URL check
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # 1. HTTPS check
    if parsed.scheme.lower() != "https":
        score += 1
        reasons.append("Website is not using HTTPS.")

    # 2. IP address instead of domain name
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 3
        reasons.append("URL uses an IP address instead of a domain name.")

    # 3. Suspicious words
    suspicious_words = [
        "login", "verify", "verification", "update",
        "secure", "account", "password", "confirm",
        "bank", "payment", "urgent", "suspended"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    if found_words:
        score += min(len(found_words), 3)
        reasons.append(
            "Suspicious keywords found: " + ", ".join(found_words)
        )

    # 4. @ symbol
    if "@" in url:
        score += 3
        reasons.append("URL contains '@', which can hide the real destination.")

    # 5. Too many subdomains
    if hostname.count(".") >= 3:
        score += 2
        reasons.append("URL contains an unusually large number of subdomains.")

    # 6. Hyphenated domain
    if "-" in hostname:
        score += 1
        reasons.append("Domain contains hyphens, which may indicate a suspicious domain.")

    # 7. Long URL
    if len(url) > 100:
        score += 1
        reasons.append("URL is unusually long.")

    # Risk classification
    if score >= 6:
        risk = "HIGH RISK"
    elif score >= 3:
        risk = "MEDIUM RISK"
    else:
        risk = "LOW RISK"

    return risk, score, reasons


def main():
    print("=" * 55)
    print("      CYBERSECURITY PHISHING DETECTION TOOL")
    print("=" * 55)

    print("\nEnter a URL to analyze.")
    print("Type 'exit' to close the tool.\n")

    while True:
        url = input("Enter URL: ").strip()

        if url.lower() == "exit":
            print("\nTool closed safely.")
            break

        if not url:
            print("Please enter a URL.\n")
            continue

        risk, score, reasons = check_url(url)

        print("\n" + "-" * 55)
        print("PHISHING ANALYSIS RESULT")
        print("-" * 55)
        print(f"URL       : {url}")
        print(f"Risk Score: {score}")
        print(f"Risk Level: {risk}")

        if reasons:
            print("\nIndicators detected:")
            for reason in reasons:
                print(f"- {reason}")
        else:
            print("\nNo obvious phishing indicators detected.")

        print("-" * 55)
        print("Note: This tool uses basic heuristic checks.")
        print("It should not be treated as a guarantee that a URL is safe.")
        print("-" * 55 + "\n")


if __name__ == "__main__":
    main()