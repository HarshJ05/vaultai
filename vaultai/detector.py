"""PII detection engine.

Two layers work together:

1. Pattern recognizers (regex) for structured PII such as Aadhaar, PAN, phone.
   Each match gets a confidence score that is raised or lowered by
     - checksum validation (Aadhaar-Verhoeff, card-Luhn, GSTIN), and
     - context words near the match ("my aadhaar is ..." vs "order id ...").
2. A spaCy NER model for unstructured PII: names, places, organizations,
   plus a small honorific / "my name is" rule for names the model misses.

Overlapping candidates are resolved by keeping the highest-confidence span.
Only spans scoring at or above `threshold` are reported.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Callable, Optional

from . import validators as v
from .names import NAME_LIST_RE


@dataclass
class Entity:
    type: str
    text: str
    start: int
    end: int
    score: float
    source: str                     # "pattern" or "ner"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = round(self.score, 2)
        return d


@dataclass
class Recognizer:
    type: str
    pattern: re.Pattern
    base_score: float
    context: tuple[str, ...] = ()          # words that raise confidence
    negative_context: tuple[str, ...] = ()  # words that lower confidence
    validator: Optional[Callable[[str], bool]] = None
    fail_validation_drops: bool = True      # reject outright if the checksum fails
    group: int = 0                          # regex group holding the value


CONTEXT_BOOST = 0.35
NEGATIVE_PENALTY = 0.45
VALIDATION_BOOST = 0.3
CONTEXT_WINDOW = 45   # characters looked at before the match
CONTEXT_AFTER = 15    # characters looked at after the match

_NEG_IDS = ("order", "invoice", "ticket", "tracking", "ref", "reference", "transaction",
            "txn", "booking", "pnr", "awb", "serial", "sku", "otp", "amount", "rs", "inr", "₹")

RECOGNIZERS: list[Recognizer] = [
    Recognizer(
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
        0.95,
    ),
    Recognizer(
        "UPI_ID",
        # handle@psp with no dot in the domain part (that would be an email)
        re.compile(r"\b[A-Za-z0-9._-]{2,64}@(?:ok(?:axis|hdfcbank|icici|sbi)|ybl|ibl|axl|apl|paytm|upi|"
                   r"sbi|icici|hdfcbank|axisbank|kotak|yesbank|idfcbank|pnb|boi|barodampay|"
                   r"airtel|jio|fbl|rbl|federal|indus|axisb|freecharge|waaxis|wahdfcbank|"
                   r"wasbi|waicici|timecosmos|abfspay|naviaxis|superyes|[a-z]{2,15})(?![\w@-])(?!\.[A-Za-z])"),
        0.8,
        context=("upi", "vpa", "gpay", "phonepe", "paytm", "pay to", "send money"),
    ),
    Recognizer(
        "GSTIN",
        re.compile(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b"),
        0.6,
        context=("gst", "gstin", "tax"),
        validator=v.gstin_valid,
    ),
    Recognizer(
        "PAN",
        # 4th character encodes holder type (P = person, C = company, ...)
        re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b"),
        0.85,
        context=("pan", "permanent account", "income tax", "it return"),
    ),
    Recognizer(
        "AADHAAR",
        re.compile(r"(?<![\d-])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d-])"),
        0.55,
        context=("aadhaar", "aadhar", "adhaar", "uidai", "uid"),
        negative_context=_NEG_IDS,
        validator=v.aadhaar_valid,
    ),
    Recognizer(
        "CREDIT_CARD",
        re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"),
        0.55,
        context=("card", "credit", "debit", "visa", "mastercard", "rupay", "amex", "cvv", "expiry"),
        negative_context=_NEG_IDS,
        validator=lambda s: v.luhn_valid(s) and v.card_prefix_valid(s),
    ),
    Recognizer(
        "PHONE",
        re.compile(r"(?<![\w+])(?:\+91[\s-]?|91[\s-]|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"),
        0.6,
        context=("phone", "mobile", "call", "contact", "whatsapp", "number", "ph", "mob", "cell", "reach me"),
        negative_context=_NEG_IDS,
    ),
    Recognizer(
        "IFSC",
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        0.75,
        context=("ifsc", "branch", "bank", "neft", "rtgs", "imps"),
    ),
    Recognizer(
        "PASSPORT",
        re.compile(r"\b[A-PR-WY][1-9]\d{6}\b"),
        0.4,
        context=("passport",),
    ),
    Recognizer(
        "VOTER_ID",
        re.compile(r"\b[A-Z]{3}\d{7}\b"),
        0.45,
        context=("voter", "epic", "election"),
    ),
    Recognizer(
        "VEHICLE_REG",
        re.compile(r"\b([A-Z]{2})[ -]?\d{1,2}[ -]?[A-Z]{1,3}[ -]?\d{4}\b"),
        0.55,
        context=("vehicle", "car", "bike", "registration", "number plate", "scooter", "rc"),
        validator=lambda s: s[:2].upper() in v.INDIAN_STATE_CODES,
    ),
    Recognizer(
        "IP_ADDRESS",
        re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)"),
        0.6,
        context=("ip", "address", "server", "login", "host"),
        negative_context=("version", "v."),
        validator=v.ipv4_valid,
    ),
    Recognizer(
        "DATE_OF_BIRTH",
        re.compile(
            r"\b(?:\d{1,2}[/.-]\d{1,2}[/.-](?:19|20)\d{2}|(?:19|20)\d{2}-\d{2}-\d{2}|"
            r"\d{1,2}(?:st|nd|rd|th)?\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?,?\s+(?:19|20)\d{2})\b",
            re.IGNORECASE,
        ),
        0.3,
        context=("born", "dob", "d.o.b", "birth", "birthday", "age"),
    ),
    Recognizer(
        "PIN_CODE",
        re.compile(r"(?<![\d-])[1-9]\d{2}\s?\d{3}(?![\d-])"),
        0.25,
        context=("pin", "pincode", "pin code", "postal", "zip", "address", "post", "live", "lives",
                 "living", "residing", "resident", "located", "city", "town", "district", "nagar", "colony", "road", "sector"),
        negative_context=_NEG_IDS,
    ),
    Recognizer(
        "BANK_ACCOUNT",
        re.compile(r"(?<!\d)\d{9,18}(?!\d)"),
        0.2,
        context=("account", "a/c", "acct", "acc no", "acc. no", "savings", "current account", "bank",
                 "ifsc", "neft", "rtgs", "imps", "transfer to", "credit to", "deposit to"),
        negative_context=_NEG_IDS,
    ),
]

# Words spaCy sometimes tags as names/orgs that are actually PII *labels*.
_NER_STOPWORDS = {
    "aadhaar", "aadhar", "pan", "upi", "ifsc", "gst", "gstin", "gdpr", "dpdp", "llm", "otp",
    "cvv", "dob", "pin", "epic", "kyc", "neft", "rtgs", "imps", "vpa", "ip", "email", "phone",
    "whatsapp", "gpay", "phonepe", "paytm", "visa", "mastercard", "rupay", "hi", "hello", "dear",
}

# Generic words the small spaCy model mislabels as organisations ("Order ID", "Server IP").
_GENERIC_TERMS = {
    "id", "ip", "invoice", "order", "server", "version", "ref", "reference", "ticket", "otp",
    "account", "card", "number", "no", "code", "bank", "branch", "upi", "api", "llm", "app",
    "dob", "address", "email", "phone", "mobile", "txn", "transaction", "pnr", "booking",
}

# Small gazetteer of Indian cities and states. spaCy's small model misses many of these
# (e.g. "Gurugram", "Noida"), so a list lookup gives cheap, reliable recall.
INDIAN_PLACES = (
    "Mumbai|Delhi|New Delhi|Bengaluru|Bangalore|Hyderabad|Ahmedabad|Chennai|Kolkata|Pune|Jaipur|"
    "Lucknow|Kanpur|Nagpur|Indore|Thane|Bhopal|Visakhapatnam|Patna|Vadodara|Ghaziabad|Ludhiana|"
    "Agra|Nashik|Faridabad|Meerut|Rajkot|Varanasi|Srinagar|Aurangabad|Dhanbad|Amritsar|Allahabad|"
    "Prayagraj|Ranchi|Howrah|Coimbatore|Jabalpur|Gwalior|Vijayawada|Jodhpur|Madurai|Raipur|Kota|"
    "Guwahati|Chandigarh|Solapur|Mysuru|Mysore|Gurugram|Gurgaon|Noida|Greater Noida|Dehradun|"
    "Udaipur|Ajmer|Bikaner|Kochi|Thiruvananthapuram|Bhubaneswar|Mangaluru|Mangalore|Surat|Goa|"
    "Shimla|Jammu|Navi Mumbai|Secunderabad|"
    "Rajasthan|Maharashtra|Karnataka|Tamil Nadu|Kerala|Gujarat|Punjab|Haryana|Uttar Pradesh|"
    "Madhya Pradesh|Bihar|West Bengal|Odisha|Telangana|Andhra Pradesh|Assam|Jharkhand|"
    "Chhattisgarh|Uttarakhand|Himachal Pradesh"
)
_PLACE_RULE = re.compile(r"\b(?:" + INDIAN_PLACES + r")\b")

_LEADING_VERBS = {"Contact", "Call", "Email", "Ask", "Escalate", "Message", "Ping", "Tell", "Inform",
                  "Meet", "Send", "Transfer", "Pay", "Notify", "Remind", "Thank", "Thanks", "Please",
                  "Customer", "Dear", "Hi", "Hello"}

_PRONOUNS = {"my", "your", "his", "her", "our", "their", "me", "i", "we", "you"}

_SPACY_MAP = {"PERSON": ("PERSON", 0.8), "GPE": ("LOCATION", 0.7), "LOC": ("LOCATION", 0.65),
              "FAC": ("LOCATION", 0.55), "ORG": ("ORGANIZATION", 0.6)}

# "my name is Ravi Kumar", "Mr. Ravi Kumar", "Dr Anita Rao" -> PERSON
_NAME_RULE = re.compile(
    r"(?:\b(?i:my name is|i am|i'm|this is|name:|mr\.?|mrs\.?|ms\.?|dr\.?|shri|smt\.?|"
    r"dear|hi|hello)\s+)"
    r"((?:[A-Z][a-z]+)(?:\s+[A-Z][a-z]+){0,2})"
)
_NOT_NAME_START = {"The", "A", "An", "Not", "Here", "Your", "My", "From", "In", "At", "On",
                   "Going", "Looking", "Writing", "Calling", "Sorry", "Happy", "Fine", "Good",
                   "Team", "All", "There", "Everyone", "Sir", "Madam", "Support", "Customer"}


class PIIDetector:
    """Find PII in text. Ablation flags let the evaluation measure each layer's value."""

    def __init__(self, threshold: float = 0.5, use_ner: bool = True, use_checksums: bool = True,
                 use_context: bool = True, use_name_list: bool = True,
                 spacy_model: str = "en_core_web_md"):
        self.threshold = threshold
        self.use_checksums = use_checksums
        self.use_context = use_context
        self.use_ner = use_ner
        self.use_name_list = use_name_list
        self._nlp = None
        if use_ner:
            try:
                import spacy
                try:
                    self._nlp = spacy.load(spacy_model, disable=["lemmatizer"])
                except OSError:  # medium model not installed: fall back to the small one
                    self._nlp = spacy.load("en_core_web_sm", disable=["lemmatizer"])
            except Exception:  # no model at all: run pattern-only rather than crash
                self.use_ner = False

    # ---- public -----------------------------------------------------------
    def detect(self, text: str, types: Optional[set[str]] = None) -> list[Entity]:
        candidates = self._pattern_candidates(text)
        if self.use_ner:
            candidates += self._ner_candidates(text)
        candidates += self._name_rule_candidates(text)
        if self.use_name_list:
            candidates += self._name_list_candidates(text)
        candidates += self._place_candidates(text)
        kept = [c for c in candidates if c.score >= self.threshold]
        result = self._resolve_overlaps(kept)
        if types is not None:
            result = [e for e in result if e.type in types]
        return sorted(result, key=lambda e: e.start)

    # ---- pattern layer ------------------------------------------------------
    def _context_text(self, text: str, start: int, end: int) -> tuple[str, str]:
        before = text[max(0, start - CONTEXT_WINDOW):start].lower()
        after = text[end:end + CONTEXT_AFTER].lower()
        return before, after

    @staticmethod
    def _has_word(haystack: str, words: tuple[str, ...]) -> Optional[str]:
        for w in words:
            if re.search(r"(?<![a-z])" + re.escape(w) + r"(?![a-z])", haystack):
                return w
        return None

    def _pattern_candidates(self, text: str) -> list[Entity]:
        out: list[Entity] = []
        for rec in RECOGNIZERS:
            for m in rec.pattern.finditer(text):
                value = m.group(0)
                start, end = m.start(), m.end()
                score = rec.base_score
                reasons = [f"pattern {rec.type} ({rec.base_score:.2f})"]

                if rec.validator is not None and self.use_checksums:
                    if rec.validator(value):
                        score += VALIDATION_BOOST
                        reasons.append("checksum/format valid")
                    elif rec.fail_validation_drops:
                        continue

                if self.use_context:
                    before, after = self._context_text(text, start, end)
                    hit = self._has_word(before + " " + after, rec.context)
                    # only the words right before the value count as negative context
                    near = text[max(0, start - 20):start].lower()
                    neg = self._has_word(near, rec.negative_context)
                    if neg:
                        # "invoice number 6126037320": the specific negative word wins over a
                        # generic positive word like "number", so no boost is applied.
                        score -= NEGATIVE_PENALTY
                        reasons.append(f"negative context '{neg}'")
                    elif hit:
                        score += CONTEXT_BOOST
                        reasons.append(f"context '{hit}'")

                out.append(Entity(rec.type, value, start, end, min(score, 0.99), "pattern", reasons))
        return out

    # ---- NER layer ------------------------------------------------------------
    def _ner_candidates(self, text: str) -> list[Entity]:
        out: list[Entity] = []
        doc = self._nlp(text)
        for ent in doc.ents:
            if ent.label_ not in _SPACY_MAP:
                continue
            etype, score = _SPACY_MAP[ent.label_]
            # drop number tokens spaCy sometimes glues on ("Pune 411001")
            toks = [t for t in ent if not (t.like_num or any(ch.isdigit() for ch in t.text))]
            if not toks:
                continue
            # spaCy sometimes glues a sentence-initial verb onto a name ("Contact Keshav Walker")
            while len(toks) > 1 and toks[0].text in _LEADING_VERBS:
                toks = toks[1:]
            span = text[toks[0].idx: toks[-1].idx + len(toks[-1].text)].strip(" .,:;'\"")
            if not span or any(ch.isdigit() for ch in span) or "@" in span:
                continue
            if span.lower() in _NER_STOPWORDS or span.isupper() and len(span) <= 5:
                continue
            if etype == "PERSON" and len(span) < 3:
                continue
            words = re.findall(r"[a-z]+", span.lower())
            # "My Aadhaar", "Your PAN": a pronoun or a PII label inside the span means
            # spaCy tagged a phrase, not a real name.
            if any(w in _GENERIC_TERMS or w in _NER_STOPWORDS or w in _PRONOUNS for w in words):
                continue
            start = toks[0].idx + text[toks[0].idx:].find(span)
            out.append(Entity(etype, span, start, start + len(span), score, "ner",
                              [f"spaCy {ent.label_}"]))
        return out

    def _name_rule_candidates(self, text: str) -> list[Entity]:
        out = []
        for m in _NAME_RULE.finditer(text):
            name = m.group(1)
            if name.split()[0] in _NOT_NAME_START:
                continue
            out.append(Entity("PERSON", name, m.start(1), m.end(1), 0.75, "pattern",
                              ["name cue (e.g. 'my name is', 'Mr.')"]))
        return out

    @staticmethod
    def _name_list_candidates(text: str) -> list[Entity]:
        return [Entity("PERSON", m.group(0), m.start(), m.end(), 0.7, "pattern",
                       ["common Indian name list"]) for m in NAME_LIST_RE.finditer(text)]

    @staticmethod
    def _place_candidates(text: str) -> list[Entity]:
        return [Entity("LOCATION", m.group(0), m.start(), m.end(), 0.7, "pattern",
                       ["known Indian city/state"]) for m in _PLACE_RULE.finditer(text)]

    # ---- overlap resolution -----------------------------------------------------
    @staticmethod
    def _resolve_overlaps(cands: list[Entity]) -> list[Entity]:
        # Two layers often find the same name with different extents ("Choudhary" vs
        # "Shalini Choudhary"). For names, the longest overlapping span is kept, with the
        # best score of the group, so a partial name never leaks the rest.
        persons = [c for c in cands if c.type == "PERSON"]
        for c in persons:
            for o in persons:
                if o is not c and o.start <= c.start and c.end <= o.end and (o.end - o.start) > (c.end - c.start):
                    o.score = max(o.score, c.score)
                    c.score = -1
        cands = [c for c in cands if c.score >= 0]
        # Highest score wins; on a tie the longer span wins; pattern beats NER.
        cands = sorted(cands, key=lambda e: (-e.score, -(e.end - e.start), e.source != "pattern"))
        chosen: list[Entity] = []
        for c in cands:
            if all(c.end <= k.start or c.start >= k.end for k in chosen):
                chosen.append(c)
        return chosen
