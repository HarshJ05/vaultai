"""Generate a labelled PII test set (eval/dataset.jsonl).

Each line: {"text": ..., "entities": [{"type", "start", "end"}], "tag": ...}

Design choices (worth explaining in an interview):
  * Values are random but REALISTIC: Aadhaar numbers carry a valid Verhoeff digit,
    cards a valid Luhn digit, GSTINs a valid mod-36 character.
  * ~30% of sentences are HARD NEGATIVES: order IDs, invoice and ticket numbers,
    prices, software versions, and 12-digit numbers that fail the Aadhaar checksum.
    A detector that flags every long number scores badly on these.
  * Half the person names come from a list the detector has NEVER seen
    ("unseen" names), so name recall is not inflated by the built-in name list.
Seeded, so the file is reproducible.
"""
import json
import random
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vaultai.validators import (gstin_check_char, luhn_check_digit,  # noqa: E402
                                verhoeff_check_digit, verhoeff_valid)
from vaultai.names import FIRST_NAMES, SURNAMES  # noqa: E402

rng = random.Random(42)

SEEN_NAMES = [f"{rng.choice(FIRST_NAMES)} {rng.choice(SURNAMES)}" for _ in range(60)]
# Not in the built-in list: tests what spaCy alone can do.
UNSEEN_FIRST = ["Tejas", "Ritika", "Omkar", "Shraddha", "Nakul", "Mrunal", "Devansh", "Ira", "Keshav",
                "Pihu", "Advait", "Lavanya", "Hrithik", "Charvi", "Parth", "Mahima", "Yuvraj", "Esha",
                "Daniel", "Sarah", "Michael", "Emma", "Carlos", "Yuki"]
UNSEEN_LAST = ["Wagh", "Bhosale", "Kale", "Chavan", "Nagpal", "Luthra", "Bose", "Kini", "Rege",
               "Sawant", "Johnson", "Fischer", "Tanaka", "Lopez", "Brown", "Walker"]
UNSEEN_NAMES = [f"{rng.choice(UNSEEN_FIRST)} {rng.choice(UNSEEN_LAST)}" for _ in range(60)]

CITIES = ["Mumbai", "Pune", "Jaipur", "Bengaluru", "Hyderabad", "Chennai", "Kolkata", "Lucknow",
          "Indore", "Noida", "Gurugram", "Ahmedabad", "Kochi", "Bhopal", "Nagpur"]
PSPS = ["okaxis", "okhdfcbank", "oksbi", "ybl", "paytm", "ibl", "upi"]
DOMAINS = ["gmail.com", "yahoo.co.in", "outlook.com", "acme.in", "company.co.in"]
STATES = ["MH", "RJ", "KA", "DL", "TN", "UP", "GJ", "HR"]


def aadhaar(fmt=True):
    base = str(rng.randint(2, 9)) + "".join(rng.choice(string.digits) for _ in range(10))
    n = base + verhoeff_check_digit(base)
    return f"{n[:4]} {n[4:8]} {n[8:]}" if fmt else n


def bad_aadhaar():
    while True:
        n = str(rng.randint(2, 9)) + "".join(rng.choice(string.digits) for _ in range(11))
        if not verhoeff_valid(n):
            return f"{n[:4]} {n[4:8]} {n[8:]}"


def pan():
    return ("".join(rng.choice(string.ascii_uppercase) for _ in range(3)) + rng.choice("PCHF")
            + rng.choice(string.ascii_uppercase) + f"{rng.randint(0, 9999):04d}" + rng.choice(string.ascii_uppercase))


def phone():
    n = str(rng.randint(6, 9)) + "".join(rng.choice(string.digits) for _ in range(9))
    style = rng.choice(["plain", "space", "plus", "dash"])
    return {"plain": n, "space": f"{n[:5]} {n[5:]}", "plus": f"+91 {n[:5]} {n[5:]}", "dash": f"+91-{n}"}[style]


def card():
    base = rng.choice(["4", "51", "52", "60"])
    base += "".join(rng.choice(string.digits) for _ in range(15 - len(base)))
    n = base + luhn_check_digit(base)
    return " ".join(n[i:i + 4] for i in range(0, 16, 4)) if rng.random() < .6 else n


def email(name):
    user = name.lower().replace(" ", rng.choice([".", "_", ""])) + rng.choice(["", str(rng.randint(1, 99))])
    return f"{user}@{rng.choice(DOMAINS)}"


def upi(name):
    return f"{name.split()[0].lower()}{rng.randint(1, 999)}@{rng.choice(PSPS)}"


def ifsc():
    return rng.choice(["HDFC", "ICIC", "SBIN", "UTIB", "KKBK", "PUNB"]) + "0" + "".join(rng.choice(string.digits) for _ in range(6))


def gstin():
    first = f"{rng.randint(1, 37):02d}" + pan() + rng.choice("123456789") + "Z"
    return first + gstin_check_char(first)


def passport():
    return rng.choice("JKLMNPRSTUVWZ") + str(rng.randint(1, 9)) + "".join(rng.choice(string.digits) for _ in range(6))


def vehicle():
    return f"{rng.choice(STATES)} {rng.randint(1, 30):02d} {rng.choice(['AB', 'CK', 'M', 'ZX'])} {rng.randint(1000, 9999)}"


def dob():
    d, m, y = rng.randint(1, 28), rng.randint(1, 12), rng.randint(1965, 2005)
    return rng.choice([f"{d:02d}/{m:02d}/{y}", f"{d} {rng.choice(['Jan', 'March', 'Aug', 'October'])} {y}"])


def ip():
    return ".".join(str(rng.randint(11, 223)) for _ in range(4))


def pincode():
    return str(rng.randint(110001, 855999))


def account():
    return "".join(rng.choice(string.digits) for _ in range(rng.choice([11, 12, 14])))


# Templates: {X:TYPE} marks a slot whose value is PII of TYPE.
POSITIVE = [
    "My name is {n:PERSON} and my Aadhaar is {a:AADHAAR}.",
    "Please call {n:PERSON} on {p:PHONE} before 5 pm.",
    "Send the invoice to {e:EMAIL} and cc the finance team.",
    "Customer {n:PERSON} shared PAN {pan:PAN} for the KYC update.",
    "Refund to account {acc:BANK_ACCOUNT}, IFSC {i:IFSC}.",
    "You can pay me at {u:UPI_ID} via GPay.",
    "Card number {c:CREDIT_CARD} was declined at checkout.",
    "{n:PERSON} lives in {city:LOCATION} and was born on {d:DATE_OF_BIRTH}.",
    "The login came from IP address {ip:IP_ADDRESS} at midnight.",
    "Our GSTIN is {g:GSTIN}, please add it to the bill.",
    "Passport number {pp:PASSPORT} expires next year.",
    "My car number is {v:VEHICLE_REG}, it was parked outside.",
    "Ship it to Sector 21, {city:LOCATION} {pin:PIN_CODE}.",
    "Hi, this is {n:PERSON}. Reach me at {p:PHONE} or {e:EMAIL}.",
    "Dear {n:PERSON}, your loan application has been approved.",
    "Aadhaar {a:AADHAAR} and mobile {p:PHONE} are linked for {n:PERSON}.",
    "Transfer the salary of {n:PERSON} to {acc:BANK_ACCOUNT} (IFSC {i:IFSC}).",
    "Escalate this to {n:PERSON} in the {city:LOCATION} office.",
    "Contact {n:PERSON} at {e:EMAIL} about the onboarding documents.",
    "DOB: {d:DATE_OF_BIRTH}, PAN: {pan:PAN}, phone: {p:PHONE}.",
]

NEGATIVE = [
    "Your order ID {num12} has been shipped.",
    "Invoice number {num10} is due on Friday.",
    "Ticket {num6} was resolved by the support team.",
    "The total comes to Rs {price} including GST.",
    "Please upgrade to version 10.2.3.4 before the release.",
    "Reference number {bad_aadhaar} for your complaint.",
    "Tracking ID {num12} is out for delivery.",
    "The meeting moved to 3 pm in conference room 4.",
    "We sold {num6} units in the last quarter.",
    "Booking PNR {num10} is confirmed for tomorrow.",
    "Summarise the quarterly report in three bullet points.",
    "Transaction {num12} failed, please retry.",
]


def fill(template):
    text, ents, pos = "", [], 0
    name = rng.choice(SEEN_NAMES if rng.random() < .5 else UNSEEN_NAMES)
    tag = "unseen_name" if name in UNSEEN_NAMES else "seen_name"
    gen = {"n": lambda: name, "a": aadhaar, "pan": pan, "p": phone, "e": lambda: email(name),
           "u": lambda: upi(name), "c": card, "acc": account, "i": ifsc, "g": gstin, "pp": passport,
           "v": vehicle, "d": dob, "ip": ip, "pin": pincode, "city": lambda: rng.choice(CITIES)}
    cache = {}
    i = 0
    while i < len(template):
        if template[i] == "{":
            j = template.index("}", i)
            key, typ = template[i + 1:j].split(":")
            if key not in cache:
                cache[key] = gen[key]()
            val = cache[key]
            ents.append({"type": typ, "start": len(text), "end": len(text) + len(val)})
            text += val
            i = j + 1
        else:
            text += template[i]
            i += 1
    return {"text": text, "entities": ents, "tag": tag if "{n:" in template else "positive"}


def fill_negative(template):
    num = lambda k: str(rng.randint(10 ** (k - 1), 10 ** k - 1))  # noqa: E731
    text = template.format(num12=num(12), num10=num(10), num6=num(6),
                           price=f"{rng.randint(100, 99999):,}", bad_aadhaar=bad_aadhaar())
    return {"text": text, "entities": [], "tag": "hard_negative"}


# HOLDOUT: different wording, written once and never used while developing the
# detector. The headline number comes from this set, not the dev set above.
POSITIVE_HOLDOUT = [
    "Kindly verify the identity of {n:PERSON}, Aadhaar no. {a:AADHAAR}, before disbursal.",
    "{n:PERSON} ({e:EMAIL}) asked us to change the registered mobile to {p:PHONE}.",
    "Beneficiary: {n:PERSON}, A/C {acc:BANK_ACCOUNT}, branch code {i:IFSC}.",
    "The applicant's PAN is {pan:PAN} and date of birth {d:DATE_OF_BIRTH}.",
    "I paid using my debit card {c:CREDIT_CARD} but the amount was not credited.",
    "We noticed suspicious activity from {ip:IP_ADDRESS}; the account belongs to {n:PERSON}.",
    "Pickup address: Flat 12, MG Road, {city:LOCATION} - {pin:PIN_CODE}.",
    "Can you whatsapp {n:PERSON} on {p:PHONE}? She is travelling to {city:LOCATION}.",
    "Supplier GST number {g:GSTIN} is missing from the purchase order.",
    "Collect the vehicle {v:VEHICLE_REG} from {n:PERSON} at the service centre.",
    "Her passport {pp:PASSPORT} was submitted along with the visa form.",
    "Send Rs 500 to {u:UPI_ID} for the team lunch.",
    "Thanks {n:PERSON}, I have forwarded your details to the HR team.",
    "Please book a cab for {n:PERSON} from {city:LOCATION} airport.",
]
NEGATIVE_HOLDOUT = [
    "Claim number {num12} is under review.",
    "SKU {num10} is out of stock in all warehouses.",
    "OTP {num6} is valid for ten minutes.",
    "AWB {num12} reached the sorting facility.",
    "Your complaint reference is {bad_aadhaar}.",
    "Revenue grew by {num6} rupees compared to last year.",
    "Write a polite reminder email about the pending report.",
    "Serial number {num10} is covered under warranty.",
]


def main(n_pos=320, n_neg=140, holdout=False):
    pos, neg = (POSITIVE_HOLDOUT, NEGATIVE_HOLDOUT) if holdout else (POSITIVE, NEGATIVE)
    rows = [fill(rng.choice(pos)) for _ in range(n_pos)] + \
           [fill_negative(rng.choice(neg)) for _ in range(n_neg)]
    rng.shuffle(rows)
    out = Path(__file__).with_name("holdout.jsonl" if holdout else "dataset.jsonl")
    out.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    print(f"wrote {len(rows)} sentences, {sum(len(r['entities']) for r in rows)} PII spans -> {out}")


if __name__ == "__main__":
    main()
    rng.seed(2026)              # new seed => new values and new name draws
    main(n_pos=300, n_neg=120, holdout=True)
