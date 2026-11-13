"""Checksum and format validators used to confirm regex candidates.

A regex only says "this looks like an Aadhaar number". A validator says
"this is mathematically a valid Aadhaar number". Using both cuts false
positives such as order IDs or random 12-digit numbers.
"""

# ---------------------------------------------------------------------------
# Verhoeff checksum (used by Aadhaar). Detects every single-digit error and
# every swap of two adjacent digits, which simple mod-10 checks miss.
# ---------------------------------------------------------------------------
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]   # inv[c] is the digit d with D[c][d] == 0


def digits_only(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())


def verhoeff_valid(number: str) -> bool:
    """True if the digit string passes the Verhoeff checksum."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    """Return the check digit to append to `number` (used to make test data)."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])


def aadhaar_valid(candidate: str) -> bool:
    d = digits_only(candidate)
    # 12 digits, cannot start with 0 or 1, must pass Verhoeff.
    return len(d) == 12 and d[0] not in "01" and verhoeff_valid(d)


# ---------------------------------------------------------------------------
# Luhn checksum (used by every payment card network).
# ---------------------------------------------------------------------------
def luhn_valid(number: str) -> bool:
    d = digits_only(number)
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(d)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def luhn_check_digit(number: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(number)):
        n = int(ch)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return str((10 - total % 10) % 10)


# ---------------------------------------------------------------------------
# PAN: 5 letters, 4 digits, 1 letter. The 4th letter encodes the holder type
# (P = person, C = company, H = HUF, F = firm, ...). Anything else is not a PAN.
# ---------------------------------------------------------------------------
PAN_HOLDER_TYPES = set("ABCFGHJLPT")


def pan_valid(candidate: str) -> bool:
    c = candidate.upper()
    return (
        len(c) == 10
        and c[:5].isalpha()
        and c[5:9].isdigit()
        and c[9].isalpha()
        and c[3] in PAN_HOLDER_TYPES
    )


def ipv4_valid(candidate: str) -> bool:
    parts = candidate.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or (len(p) > 1 and p[0] == "0") or int(p) > 255:
            return False
    return True


# Indian vehicle registration state / UT codes.
VEHICLE_STATE_CODES = {
    "AN", "AP", "AR", "AS", "BR", "CH", "CG", "DD", "DL", "GA", "GJ", "HR",
    "HP", "JK", "JH", "KA", "KL", "LA", "LD", "MP", "MH", "MN", "ML", "MZ",
    "NL", "OD", "OR", "PY", "PB", "RJ", "SK", "TN", "TS", "TR", "UP", "UK",
    "WB", "BH",
}

INDIAN_STATE_CODES = VEHICLE_STATE_CODES


def card_prefix_valid(number: str) -> bool:
    """Known card network prefixes: Visa 4, Mastercard 51-55/2221-2720, Amex 34/37,
    RuPay 60/65/81/82/508, Diners 36/38, Discover 6011."""
    d = digits_only(number)
    if d.startswith("4"):
        return len(d) in (13, 16, 19)
    if d[:2] in {"34", "37"}:
        return len(d) == 15
    if d[:2] in {"51", "52", "53", "54", "55"} or 2221 <= int(d[:4]) <= 2720:
        return len(d) == 16
    if d[:2] in {"60", "65", "81", "82", "36", "38"} or d[:3] == "508" or d[:4] == "6011":
        return 14 <= len(d) <= 19
    return False


# GSTIN: 2-digit state + PAN + entity number + 'Z' + check character (mod-36 checksum).
_GST_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_check_char(first14: str) -> str:
    total = 0
    for i, ch in enumerate(first14):
        val = _GST_CHARS.index(ch) * (2 if i % 2 else 1)
        total += val // 36 + val % 36
    return _GST_CHARS[(36 - total % 36) % 36]


def gstin_valid(candidate: str) -> bool:
    c = candidate.upper()
    if len(c) != 15 or any(ch not in _GST_CHARS for ch in c):
        return False
    return pan_valid(c[2:12]) and gstin_check_char(c[:14]) == c[14]
