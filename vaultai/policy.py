"""Metadata for every PII type: how risky it is and how it should be treated.

This drives the risk score shown in the app and the compliance notes.
Keeping it in one table makes it easy to explain and to change.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class PIIType:
    code: str          # used in tokens, e.g. <AADHAAR_1>
    label: str         # human-readable name
    category: str      # grouping shown in the UI
    risk: int          # 1 (low) .. 5 (critical)
    redact_default: bool = True


PII_TYPES = {
    t.code: t
    for t in [
        PIIType("AADHAAR", "Aadhaar number", "Government ID", 5),
        PIIType("PAN", "PAN card number", "Government ID", 4),
        PIIType("PASSPORT", "Indian passport number", "Government ID", 5),
        PIIType("VOTER_ID", "Voter ID (EPIC)", "Government ID", 4),
        PIIType("CREDIT_CARD", "Payment card number", "Financial", 5),
        PIIType("BANK_ACCOUNT", "Bank account number", "Financial", 4),
        PIIType("IFSC", "IFSC bank branch code", "Financial", 2),
        PIIType("UPI_ID", "UPI ID", "Financial", 3),
        PIIType("GSTIN", "GST registration number", "Business ID", 2),
        PIIType("PHONE", "Phone number", "Contact", 3),
        PIIType("EMAIL", "Email address", "Contact", 3),
        PIIType("IP_ADDRESS", "IP address", "Online identifier", 2),
        PIIType("DATE_OF_BIRTH", "Date of birth", "Personal", 3),
        PIIType("PIN_CODE", "Postal PIN code", "Location", 1),
        PIIType("VEHICLE_REG", "Vehicle registration number", "Personal", 2),
        PIIType("PERSON", "Person name", "Identity", 3),
        PIIType("LOCATION", "Location / address", "Location", 2),
        PIIType("ORGANIZATION", "Organization name", "Context", 1, redact_default=False),
    ]
}


def risk_score(entity_codes: list[str]) -> dict:
    """Turn the detected PII types into a 0-100 risk score plus a level.

    The score grows with the riskiest item found and with how many different
    kinds of PII are combined (combinations make re-identification easier).
    """
    if not entity_codes:
        return {"score": 0, "level": "None", "categories": []}
    risks = [PII_TYPES[c].risk for c in entity_codes if c in PII_TYPES]
    distinct = len(set(entity_codes))
    score = min(100, max(risks) * 15 + (distinct - 1) * 8 + (len(entity_codes) - 1) * 2)
    level = "Critical" if score >= 75 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    cats = sorted({PII_TYPES[c].category for c in entity_codes if c in PII_TYPES})
    return {"score": score, "level": level, "categories": cats}


COMPLIANCE_NOTES = {
    "erasure": "Right to erasure: GDPR Art. 17 and India's DPDP Act 2023 (s.12) let a person ask for their data to be deleted.",
    "consent": "Consent: under the DPDP Act 2023 personal data is processed on the basis of consent, which can be withdrawn; expired consent blocks processing here.",
    "minimisation": "Data minimisation: the LLM only ever receives tokens, never the raw personal data.",
    "retention": "Storage limitation: vault entries expire after the configured retention period and are purged.",
}


# ---- Cross-border transfer rules ------------------------------------------------------
# Where the AI model's server sits decides whether data may be sent there.
# Even tokenized text counts: GDPR treats pseudonymised data as personal data (Recital 26),
# so transfer rules still apply to what we send.
import os  # noqa: E402

REGIONS = {
    "IN": {"label": "India (Mumbai)", "eu": False, "adequacy": False},
    "EU": {"label": "EU (Frankfurt)", "eu": True, "adequacy": True},
    "UK": {"label": "United Kingdom (London)", "eu": False, "adequacy": True},
    "JP": {"label": "Japan (Tokyo)", "eu": False, "adequacy": True},
    "US": {"label": "United States (Virginia)", "eu": False, "adequacy": False, "dpf": True},
    "SG": {"label": "Singapore", "eu": False, "adequacy": False},
}

# DPDP Act 2023 s.16: transfers abroad are allowed EXCEPT to countries the central
# government restricts by notification. Kept configurable, empty by default.
DPDP_RESTRICTED = {c.strip().upper() for c in os.environ.get("DPDP_RESTRICTED", "").split(",") if c.strip()}


def transfer_check(region: str, framework: str, safeguards: bool = False) -> dict:
    """Return {'allowed': bool, 'basis': str} for sending data to `region`.

    safeguards = the AI provider has Standard Contractual Clauses (GDPR Art. 46) in
    place, or for the US, is certified under the EU-US Data Privacy Framework.
    """
    r = REGIONS.get(region)
    if r is None:
        return {"allowed": False, "basis": f"Unknown region '{region}'."}
    if framework == "GDPR":
        if r["eu"]:
            return {"allowed": True, "basis": "Data stays in the EU/EEA: no transfer restriction."}
        if r["adequacy"]:
            return {"allowed": True, "basis": f"{r['label']} has an EU adequacy decision (GDPR Art. 45)."}
        if safeguards:
            how = "Data Privacy Framework certification or SCCs" if r.get("dpf") else "Standard Contractual Clauses"
            return {"allowed": True, "basis": f"Allowed through appropriate safeguards: {how} (GDPR Art. 46)."}
        if r.get("dpf"):
            return {"allowed": False,
                    "basis": f"Blocked: EU adequacy for {r['label']} covers only providers certified under the "
                             "Data Privacy Framework, and no certification or SCCs are confirmed."}
        return {"allowed": False,
                "basis": f"Blocked: {r['label']} has no EU adequacy decision and no safeguards are in place (GDPR Art. 46)."}
    # DPDP
    if region == "IN":
        return {"allowed": True, "basis": "Data stays in India."}
    if region in DPDP_RESTRICTED:
        return {"allowed": False, "basis": f"Blocked: {r['label']} is on the restricted list notified under DPDP s.16."}
    return {"allowed": True,
            "basis": f"Allowed: {r['label']} is not on the government's restricted list (DPDP s.16)."}
