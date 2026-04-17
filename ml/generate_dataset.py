import random
import csv
import string

# Keywords often used in phishing
keywords = ["login", "secure", "verify", "account", "update"]

# Generate random word (domain name)
def random_word(min_len=5, max_len=10):
    length = random.randint(min_len, max_len)
    return ''.join(random.choices(string.ascii_lowercase, k=length))

# Generate SAFE domain
def generate_safe():
    tlds = [".com", ".net", ".org", ".io", ".co"]

    name = random_word()
    domain = name + random.choice(tlds)

    return {
        "url": domain,
        "length": len(domain),
        "hasNumbers": 0,
        "numDots": domain.count("."),
        "hasHyphen": 0,
        "hasAtSymbol": 0,
        "label": 0
    }

# Generate SPOOF domain
def generate_spoof():
    base = random_word()

    patterns = [
        base.replace("o", "0"),                        # typo attack
        base + str(random.randint(1, 99)),             # numbers
        random.choice(keywords) + "-" + base,          # keyword prefix
        base + "-" + random.choice(keywords),          # keyword suffix
        base + ".fake-site.com",                       # subdomain attack
        random.choice(keywords) + "." + base + ".com", # nested subdomain
        base + "@phishing.com"                         # @ attack
    ]

    domain = random.choice(patterns)

    return {
        "url": domain,
        "length": len(domain),
        "hasNumbers": int(any(char.isdigit() for char in domain)),
        "numDots": domain.count("."),
        "hasHyphen": int("-" in domain),
        "hasAtSymbol": int("@" in domain),
        "label": 1
    }

# Generate dataset
rows = []

for _ in range(300):
    rows.append(generate_safe())
    rows.append(generate_spoof())

# Save CSV
with open("ml/generated_dataset.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print("Dataset generated successfully!")