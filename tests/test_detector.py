import pytest

from vaultai import validators as v
from vaultai.detector import PIIDetector


@pytest.fixture(scope="module")
def det():
    return PIIDetector()


def types(det, text):
    return [(e.type, e.text) for e in det.detect(text)]


# ---- validators --------------------------------------------------------------------
def test_verhoeff_generator_matches_validator():
    for base in ["23456789012", "94667740808", "50000000000", "99999999999"]:
        assert v.verhoeff_valid(base + v.verhoeff_check_digit(base))


def test_aadhaar_rules():
    good = "2345678901" + "2"
    good = good[:11] + v.verhoeff_check_digit(good[:11])
    assert v.aadhaar_valid(good)
    assert not v.aadhaar_valid("1" + good[1:])               # cannot start with 0/1
    bad_last = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert not v.aadhaar_valid(bad_last)                     # single-digit error caught


def test_luhn_and_card_prefix():
    assert v.luhn_valid("4111 1111 1111 1111") and v.card_prefix_valid("4111111111111111")
    assert not v.luhn_valid("4111 1111 1111 1112")


def test_pan_holder_type():
    assert v.pan_valid("ABCPM1234K")
    assert not v.pan_valid("ABCXM1234K")                     # X is not a holder type


def test_gstin_checksum():
    first = "27AAPFU0939F1Z"
    assert v.gstin_valid(first + v.gstin_check_char(first))
    assert not v.gstin_valid(first + "0") or v.gstin_check_char(first) == "0"


# ---- detector ----------------------------------------------------------------------
def test_detects_core_indian_pii(det):
    found = types(det, "Aadhaar 2345 6789 0124, PAN ABCPM1234K, call +91 98765 43210, "
                       "pay rohan@okaxis, IFSC HDFC0001234, mail rohan.m@gmail.com")
    kinds = {t for t, _ in found}
    assert {"AADHAAR", "PAN", "PHONE", "UPI_ID", "IFSC", "EMAIL"} <= kinds


def test_invalid_aadhaar_not_flagged(det):
    assert not [t for t, _ in types(det, "Aadhaar 2345 6789 0125") if t == "AADHAAR"]


def test_order_and_invoice_numbers_ignored(det):
    for text in ["Your order ID 9876543210 has shipped.", "Invoice number 6126037320 is due."]:
        assert not [t for t, _ in types(det, text) if t in {"PHONE", "AADHAAR", "BANK_ACCOUNT"}]


def test_indian_names(det):
    assert ("PERSON", "Priya Sharma") in types(det, "Call Priya Sharma on 9123456780")
    assert ("PERSON", "Anjali") in types(det, "Dear Anjali, your loan is approved.")


def test_no_pronoun_names(det):
    assert all(t != "PERSON" for t, _ in types(det, "My Aadhaar is 2345 6789 0124"))


def test_upi_vs_email(det):
    found = {text: kind for kind, text in types(det, "pay rohan@okaxis or mail rohan@gmail.com")}
    assert found.get("rohan@okaxis") == "UPI_ID"
    assert found.get("rohan@gmail.com") == "EMAIL"


def test_no_pii(det):
    assert det.detect("Summarise the quarterly report in three bullet points.") == []
