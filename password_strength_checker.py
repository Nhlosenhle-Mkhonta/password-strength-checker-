
import re
import math
import argparse
import hashlib

# Small sample common password list for demonstration (ethical, short)
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "letmein", "admin", "welcome"
}

def char_classes(password):
    classes = {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^\w\s]", password))
    }
    return classes

def estimate_entropy(password):
    # Estimate character set size
    classes = char_classes(password)
    pool = 0
    if classes["lower"]: pool += 26
    if classes["upper"]: pool += 26
    if classes["digit"]: pool += 10
    if classes["symbol"]: pool += 32  # rough estimate for printable symbols
    if pool == 0:
        pool = 1
    entropy = math.log2(pool) * len(password)
    return entropy

def detect_patterns(password):
    findings = []
    # repeated characters
    if re.search(r"(.)\1\1", password):
        findings.append("Contains repeated characters (e.g., aaa)")
    # sequential digits or letters (length >=4)
    seq_found = False
    for i in range(len(password) - 3):
        chunk = password[i:i+4].lower()
        if chunk.isalpha() and ''.join(sorted(chunk)) == chunk:
            seq_found = True
        if chunk.isdigit() and ''.join(sorted(chunk)) == chunk:
            seq_found = True
    if seq_found:
        findings.append("Contains sequential characters (e.g., 1234 or abcd)")
    # common substrings
    lowered = password.lower()
    for s in ["password", "admin", "welcome", "user", "qwerty"]:
        if s in lowered:
            findings.append(f"Contains common substring '{s}'")
    # keyboard patterns (simple detection)
    if re.search(r"(qwerty|asdf|zxcv)", lowered):
        findings.append("Contains keyboard pattern (e.g., qwerty)")
    return findings

def check_common(password):
    return password.lower() in COMMON_PASSWORDS

def score_password(password):
    length = len(password)
    classes = char_classes(password)
    entropy = estimate_entropy(password)
    patterns = detect_patterns(password)
    is_common = check_common(password)
    score = 0
    # Base scoring
    if length >= 12: score += 30
    elif length >= 8: score += 15
    else: score += 5
    # Character classes
    score += sum([10 for v in classes.values() if v])
    # Entropy bonus
    if entropy >= 60: score += 30
    elif entropy >= 40: score += 15
    # Penalties
    if patterns:
        score -= 20
    if is_common:
        score -= 40
    # Normalize to 0-100
    score = max(0, min(100, score))
    return {
        "score": score,
        "length": length,
        "entropy": round(entropy, 2),
        "classes": classes,
        "patterns": patterns,
        "is_common": is_common
    }

def feedback(result):
    tips = []
    if result["length"] < 12:
        tips.append("Increase length to at least 12 characters.")
    if not result["classes"]["upper"]:
        tips.append("Add uppercase letters.")
    if not result["classes"]["lower"]:
        tips.append("Add lowercase letters.")
    if not result["classes"]["digit"]:
        tips.append("Add digits.")
    if not result["classes"]["symbol"]:
        tips.append("Add symbols (e.g., !@#$%).")
    if result["is_common"]:
        tips.append("Avoid common passwords or dictionary words.")
    if result["patterns"]:
        tips.append("Avoid sequential or repeated patterns.")
    if result["entropy"] < 50:
        tips.append("Aim for higher entropy (use unpredictable characters and length).")
    if not tips:
        tips.append("Password looks strong. Consider using a password manager to generate/store unique passwords.")
    return tips

def analyze_password(password):
    res = score_password(password)
    res["advice"] = feedback(res)
    # hashed sample (do not store plaintext in logs)
    res["sha256_sample"] = hashlib.sha256(password.encode('utf-8')).hexdigest()[:16]
    return res

def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("--password", help="Password to check")
    parser.add_argument("--file", help="File with one password per line")
    args = parser.parse_args()
    results = {}
    if args.password:
        results[args.password] = analyze_password(args.password)
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            for line in f:
                pwd = line.strip()
                if not pwd:
                    continue
                results[pwd] = analyze_password(pwd)
    else:
        pwd = input("Enter password to evaluate: ")
        results[pwd] = analyze_password(pwd)
    # Print JSON summary (safe: do not print full plaintext in shared logs)
    for pwd, res in results.items():
        print("\n--- Password Analysis ---")
        print(f"Score: {res['score']}/100")
        print(f"Length: {res['length']}")
        print(f"Estimated entropy: {res['entropy']} bits")
        print(f"Character classes: {res['classes']}")
        print(f"Common password: {res['is_common']}")
        if res['patterns']:
            print("Detected patterns: " + "; ".join(res['patterns']))
        print("Advice:")
        for t in res['advice']:
            print(" - " + t)
        print(f"Sample hash (sha256 prefix): {res['sha256_sample']}")


if __name__ == "__main__":
    main()
