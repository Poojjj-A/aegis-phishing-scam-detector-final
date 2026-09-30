"""
generate_dataset.py
--------------------
Builds data/dataset.csv - a labeled set of phishing/scam vs. legitimate
messages used to train the TF-IDF + Logistic Regression classifier.

Real-world phishing corpora (e.g. the Nazario phishing corpus, the UCI SMS
Spam Collection) are the gold standard and are recommended as a drop-in
upgrade - see README "Improving the model". Since this environment has no
internet access, this script instead builds a sizeable, diverse dataset
programmatically from curated message templates covering email phishing,
SMS smishing, and social-media/romance/job scams, mixed against a wide
variety of legitimate everyday messages. This keeps the pipeline fully
reproducible with `python generate_dataset.py`.
"""

import csv
import random

random.seed(42)

BRANDS = ["Amazon", "PayPal", "Netflix", "Apple", "Microsoft", "Chase Bank",
          "Bank of America", "Wells Fargo", "USPS", "FedEx", "DHL",
          "Instagram", "Facebook", "LinkedIn", "Coinbase", "the IRS"]

FAKE_DOMAINS = ["secure-verify-login.top", "account-update.xyz", "confirm-billing.click",
                "paypa1-secure.com", "amaz0n-support.net", "verify-appleid.work",
                "bankofamerica.login-alert.ru", "usps-tracking.info", "netfliix-billing.com",
                "192.168.77.10/login", "bit.ly/3xVerify", "tinyurl.com/acct-verify",
                "irs-refund-claim.gq", "chase-secure.online", "fedex-redelivery.cam"]

REAL_LOOKING_URLS = ["https://www.amazon.com/orders", "https://mail.google.com",
                     "https://www.linkedin.com/feed", "https://github.com/settings",
                     "https://www.irs.gov/refunds", "https://www.chase.com/online",
                     "https://calendar.google.com/event", "https://zoom.us/j/1234567"]

PHISHING_EMAIL_TEMPLATES = [
    "Dear Customer, your {brand} account has been suspended due to unusual activity. "
    "Verify your identity immediately at {url} or your account will be permanently closed within 24 hours.",

    "URGENT: We detected a login attempt to your {brand} account from a new device. "
    "If this wasn't you, confirm your password and security details now at {url} to avoid suspension.",

    "Congratulations! You have won a $1,000 {brand} gift card. Claim your prize before it expires "
    "by clicking {url} and entering your card number to cover a small shipping fee.",

    "Your {brand} payment of $249.99 could not be processed. Update your billing information "
    "within 12 hours at {url} to avoid service interruption and late penalties.",

    "This is {brand} Security. Your account will be locked unless you verify your SSN and date of "
    "birth at {url} immediately. Failure to respond will result in legal action.",

    "Final notice from {brand}: An invoice #{inv} for ${amt} is overdue. Pay now at {url} to avoid "
    "penalties and referral to collections.",

    "Dear valued customer, we noticed a problem with your {brand} billing details. Please confirm "
    "your account information at {url} within 24 hours or access will be restricted.",

    "{brand} Alert: Your package could not be delivered due to an incomplete address. Reschedule "
    "delivery and pay a small redelivery fee at {url} within 48 hours.",

    "Your {brand} account shows suspicious sign-in activity from a foreign IP address. Act now and "
    "verify your account at {url}, or it will be deactivated tonight.",

    "You have been selected to receive a tax refund of ${amt} from {brand}. Submit your bank details "
    "at {url} within 3 days to claim your refund.",
]

SMS_SMISHING_TEMPLATES = [
    "{brand}: Your card ending 4432 was charged ${amt}. If this wasn't you, verify now: {url}",
    "USPS: Your package is on hold due to unpaid customs fee of $2.99. Pay here: {url}",
    "Congrats! You've won a free iPhone 15 from {brand}. Claim now, offer expires today: {url}",
    "Your {brand} account has been locked. Verify your identity within 24 hrs: {url}",
    "ALERT: Unusual sign-in detected on your account. Confirm it's you or account will be suspended: {url}",
    "Your bank account will be frozen due to unusual activity. Verify your PIN immediately: {url}",
    "You have a pending refund of ${amt}. Click to claim before it expires: {url}",
    "Delivery attempt failed. Reschedule your {brand} package here (small fee applies): {url}",
    "FINAL WARNING: Unpaid toll of $9.75. Pay now to avoid late fees and DMV report: {url}",
    "Your one-time password is required to confirm a large withdrawal. Enter your OTP here: {url}",
]

SOCIAL_SCAM_TEMPLATES = [
    "Hi, I'm a recruiter for {brand}. We loved your profile! Start earning $500/day working from home, "
    "just send your bank details to get set up: {url}",
    "I've been thinking about you all day. I need $800 to cover an emergency, can you wire it to this "
    "account? I'll pay you back double next week: {url}",
    "You've been pre-approved for a $10,000 loan with 0% interest! No credit check needed. Apply now "
    "and provide your SSN here: {url}",
    "Investment opportunity: Turn $200 into $5,000 in one week with our exclusive crypto trading bot. "
    "Limited spots, deposit now: {url}",
    "Hello dear, I am a soldier overseas and need help transferring $2,000,000 inheritance. Share your "
    "account details and I will reward you generously: {url}",
    "Work from home job: Earn $300/day, no experience needed! Just pay a $50 registration fee at {url} "
    "to start immediately.",
]

# --- Legitimate message templates (should NOT be flagged) ---
LEGIT_TEMPLATES = [
    "Hey, are we still on for lunch tomorrow at 1pm? Let me know if that works for you.",
    "Your order #{inv} has shipped and is expected to arrive on Thursday. Track it anytime in your account.",
    "Reminder: your dentist appointment is scheduled for Monday at 10:30am. Reply CONFIRM or call to reschedule.",
    "Hi team, attaching the meeting notes from today's stand-up. Let me know if I missed anything.",
    "Thanks for signing up for our newsletter! You can update your preferences anytime from your account settings.",
    "Your monthly statement is now available to view in your online banking portal.",
    "Mom, I landed safely! Will call you once I get to the hotel. Love you.",
    "Hi, just following up on the proposal I sent last week - happy to jump on a call if useful.",
    "Your subscription renews on the 14th. No action is needed unless you'd like to make changes.",
    "Great seeing you at the conference! Let's grab coffee sometime next month.",
    "Your ride is arriving in 3 minutes. Look for a blue sedan near the main entrance.",
    "The report you requested is attached. Let me know if the numbers for Q3 look right.",
    "Happy birthday! Hope you have a wonderful day, let's catch up this weekend.",
    "Your prescription refill is ready for pickup at the pharmacy.",
    "Class is moved to room 204 for tomorrow's lecture. See you there.",
    "Thanks for your payment of $45.00 for this month's electricity bill. Your account is up to date.",
    "Can you send over the slides before the review call at 3pm?",
    "Your flight AA1234 departs at 6:45am from Gate B12. Check in online to save time at the airport.",
    "Just checking in - how did the interview go? Would love to hear how it went.",
    "The library book you reserved is ready for pickup, please collect it within 5 days.",
    "Your Wi-Fi router firmware has been updated automatically, no action needed.",
    "Reminder that our book club meets this Thursday at 7pm, same as usual.",
    "Here's the recipe I mentioned - let me know how it turns out if you try it!",
    "Your feedback on the last sprint was really helpful, thanks for taking the time.",
    "The plumber will arrive between 9-11am tomorrow to fix the leak.",
]

LEGIT_WITH_URL_TEMPLATES = [
    "Here's the shared doc we discussed: {url}",
    "You can view the calendar invite here: {url}",
    "Check out this article, thought you'd find it interesting: {url}",
    "Our repo's CI just passed, see the build log here: {url}",
    "Your monthly newsletter is ready to read: {url}",
]


def money():
    return random.choice([49, 99, 149, 249, 500, 999, 1200, 2500])


def rows():
    data = []

    for t in PHISHING_EMAIL_TEMPLATES:
        for _ in range(6):
            brand = random.choice(BRANDS)
            url = random.choice(FAKE_DOMAINS)
            text = t.format(brand=brand, url=url, inv=random.randint(10000, 99999), amt=money())
            data.append((text, "phishing_email"))

    for t in SMS_SMISHING_TEMPLATES:
        for _ in range(6):
            brand = random.choice(BRANDS)
            url = random.choice(FAKE_DOMAINS)
            text = t.format(brand=brand, url=url, amt=money())
            data.append((text, "smishing"))

    for t in SOCIAL_SCAM_TEMPLATES:
        for _ in range(6):
            url = random.choice(FAKE_DOMAINS)
            brand = random.choice(BRANDS)
            text = t.format(brand=brand, url=url)
            data.append((text, "social_scam"))

    for t in LEGIT_TEMPLATES:
        for _ in range(5):
            text = t.format(inv=random.randint(10000, 99999))
            data.append((text, "legitimate"))

    for t in LEGIT_WITH_URL_TEMPLATES:
        for _ in range(5):
            url = random.choice(REAL_LOOKING_URLS)
            data.append((t.format(url=url), "legitimate"))

    random.shuffle(data)
    return data


def main():
    data = rows()
    with open("data/dataset.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "category", "label"])
        for text, category in data:
            label = 0 if category == "legitimate" else 1
            writer.writerow([text, category, label])
    print(f"Wrote {len(data)} rows to data/dataset.csv")


if __name__ == "__main__":
    main()
