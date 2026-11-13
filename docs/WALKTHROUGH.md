# VaultAI v2: step-by-step walkthrough

Read this before any interview. It explains what each part does, why it was built that way, and the questions you're likely to get. Each section points to the file that does the work.

---

## 0. The 30-second pitch

> "People paste personal data into AI chatbots: Aadhaar, phone numbers, bank details. VaultAI sits in front of the LLM. It automatically detects personal data, with no labelling by the user, using validated patterns and an NLP model. It replaces each item with a random token like `[[V_K7Q2MX9A]]`, stores the real values encrypted, sends only the tokens to the model, and restores the real values in the reply. On a held-out test set it reaches 96.5% F1, and I measured how much each detection layer contributes. It also handles consent, right-to-erasure and audit logging for GDPR and India's DPDP Act."

---

## 1. The flow, end to end (`vaultai/api.py`, `/api/chat`)

1. **Consent check.** If the session has no active consent, the request is blocked (HTTP 403) and the block is logged.
2. **Detect.** `PIIDetector.detect(text)` returns a list of entities: type, exact character position and confidence.
3. **Tokenize.** `Vault.redact()` replaces each entity with a random token and stores the real value encrypted.
4. **Call the LLM** with the redacted text only (`vaultai/llm.py`).
5. **Restore.** `Vault.restore_segments()` finds tokens in the reply and decrypts them back. It tolerates small LLM slips, like a dropped bracket.
6. **Return every stage** so the UI can show "what the model received" next to "what you see".

**Likely question: "Why replace right-to-left?"** Each replacement changes the string's length. If you replace from the end of the text first, the positions of the earlier entities don't move.

---

## 2. Detection (`vaultai/detector.py`, `vaultai/validators.py`)

There are four layers, each switchable on and off for the evaluation.

**Layer 1: regex patterns.** Each PII type has a pattern and a base confidence. Example: a PAN is 5 letters, 4 digits, 1 letter, and the 4th letter must be a holder type (P = person, C = company…), so `ABCXM1234K` is rejected.

**Layer 2: checksums.** A regex only says "this looks like an Aadhaar". A checksum says "this is mathematically valid".
- **Aadhaar uses Verhoeff.** It catches every single-digit typo and every swap of two neighbouring digits.
- **Cards use Luhn,** plus known network prefixes (Visa 4, Mastercard 51–55, RuPay 60/65…).
- **GSTIN has its own mod-36 check character.**
- **Result:** wrongly flagged hard negatives drop from 55% to 18%.

**Layer 3: context words.** The 45 characters before and 15 after the match are checked.
- **Positive words raise the score:** "aadhaar", "call", "ifsc".
- **Negative words right before the number lower it:** "order", "invoice", "otp".
- **A negative word always wins over a generic positive word.** "Invoice number 6126037320" is not a phone number, even though "number" is a phone context word.
- **Result:** false alarms drop to 2%.

**Layer 4: names and places.**
- **spaCy `en_core_web_md` NER** finds people, places and organisations.
- **The weakness:** spaCy is trained mostly on Western news, so it missed "Call Priya Sharma".
- **The fix:** an Indian first-name and surname list (`names.py`), greeting cues ("Dear Anjali", "my name is…") and a list of Indian cities.
- **Clean-up rules:** remove verbs spaCy glues onto names ("Contact Keshav Walker"), and drop phrases with pronouns or PII labels in them ("My Aadhaar").
- **Result:** recall jumps from 70% to 98%.

**Overlap resolution.** Several layers can claim the same text. The highest score wins. For names, the **longest** overlapping span wins, so "Choudhary" can't be kept while "Shalini" leaks.

**Likely question: "Why not just ask an LLM to find the PII, like v1 did?"** Sending text to an external LLM to find personal data defeats the purpose, because the PII leaves your system before it's protected. A local engine is also faster, free, deterministic and testable. An LLM could be added later as an optional second opinion for hard cases.

---

## 3. The vault (`vaultai/vault.py`)

| Column | What it holds |
|---|---|
| `placeholder` | the random token, e.g. `[[V_K7Q2MX9A]]` |
| `ciphertext` | the real value, Fernet-encrypted (AES-128-CBC + HMAC-SHA256) |
| `fingerprint` | HMAC-SHA256 of the *normalised* value, using a secret key |
| `expires_at` | for the retention policy |

**Why two keys?** The encryption key protects values at rest. The HMAC key makes the fingerprint impossible to reverse by guessing. Without a secret key, an attacker could hash all 10 billion phone numbers and match them.

**Why a fingerprint at all?**
1. **Consistency.** `98765 43210` and `+91-9876543210` normalise to the same digits, so they get the same token and the LLM understands it's one person.
2. **Erasure without decryption.** To delete someone's phone number everywhere, compute its fingerprint and delete the matching rows. Nothing is decrypted.

**Why random tokens instead of `<PHONE_1>`?** A typed placeholder still leaks *what kind* of data was there. A random token leaks nothing. The trade-off is that the LLM doesn't know whether a token is a name or a number, so for tasks that need that, `TOKEN_STYLE=typed` switches to typed placeholders. Being able to name this trade-off is a strong interview answer.

**Restore safety.** Tokens that are unknown, expired or erased become `[REDACTED]`, never a guess. Sessions are isolated, so another session's `<EMAIL_1>` can't be decrypted.

**Bug I found and fixed:** the Verhoeff "inverse" table had wrong values. I caught it because the evaluation said valid Aadhaar numbers were being missed. Comparing against the `python-stdnum` library showed my test-data generator was producing invalid numbers. **The lesson: test your test data too.**

---

## 4. Compliance features

- **Consent** (DPDP Act s.6, GDPR Art. 6): given for a set time, can be withdrawn, and chat is blocked without it.
- **Right to erasure** (GDPR Art. 17, DPDP s.12): type just the value, with no type needed. It's erased across all sessions. You can also erase a whole session.
- **Retention / storage limitation:** entries expire (default 24 h) and are purged automatically.
- **Data minimisation:** the LLM only ever sees random tokens.
- **Audit log:** every action is recorded, but values are never logged.
- **Cross-border transfers** (GDPR Art. 45/46, DPDP s.16): choose where the AI server runs. Under GDPR, sending to the US or Singapore is blocked unless safeguards are confirmed. Under DPDP, sending abroad is allowed unless the country is on the restricted list. Even tokenized text counts as personal data under GDPR (Recital 26, pseudonymised data), which is why the check still applies.

Say clearly in interviews: *"This is a technical control that supports compliance. It isn't legal certification."*

---

## 4a. Retries and fallback (`vaultai/llm.py`)

Free AI APIs are sometimes overloaded (HTTP 503) or rate-limited (429). The client retries each model twice with backoff (1 s, then 2 s). If the model stays busy, or Google has retired it (404), it moves to the next model in `GEMINI_FALLBACK_MODELS`. A bad key (400/401/403) fails immediately, since retrying can't fix it. The UI shows which model actually answered. **Interview line:** "I designed for the provider failing, not just for the happy path."

## 4b. Admin console (`vaultai/admin.py`, `/api/admin/*`)

**Why it exists:** random tokens mean even the sender can't see what `[[V_7A9NEWHP]]` was. A business still needs authorised staff to look up a record, for a dispute or a legal request. So there's an admin role.

- **Login:** the username and password come from `.env`. The password is kept only as an **scrypt hash**, and comparisons are constant-time, so timing doesn't leak anything. Success gives a random session token in an **HttpOnly, SameSite=Strict cookie**, so JavaScript can't read it. It expires after 30 minutes idle.
- **Brute-force protection:** 5 wrong passwords from one address lock it for 5 minutes. Failed and successful logins are audited.
- **Masked by default:** the records table shows `•••• •••• 0124` or `R•••• M••••`. **Reveal** decrypts one value for 30 seconds and writes `admin_revealed · by admin '<name>'` to the audit log.
- **Search by real value without decrypting the vault:** the search text is fingerprinted, exactly like erasure.
- **Users can no longer see the all-sessions audit log.** That view is admin-only now.

**Likely question: "Isn't an admin who can decrypt everything a risk?"** Yes. That's why access is least-privilege (masked by default), every reveal is logged, and in production you'd add per-admin accounts, 2FA, and alerts on unusual reveal volumes.

## 5. Evaluation (`eval/`), your strongest interview topic

- **`make_dataset.py`** generates labelled sentences with realistic values (valid checksums) and **hard negatives**: order IDs, OTPs, invoice numbers, and 12-digit numbers that *fail* the Aadhaar checksum.
- **Two sets:**
  - The **dev set** was used while fixing bugs.
  - The **holdout set** has different wording and a different seed, was written once and was never tuned on. **Always quote the holdout number: 96.5% F1 (94.8% precision, 98.2% recall).**
- **Unseen names:** half the names come from a list the engine doesn't know, to test spaCy honestly (92% recall).
- **Ablation:** the same data with layers switched off shows what each layer is worth (see the README table).
- **Strict scoring:** type **and** exact span must match.

**Known errors, and what to say about them:**
- **"MG Road" flagged as a location.** It *is* part of an address. My labels missed it, so it's a labelling issue.
- **A few random 12-digit numbers pass Verhoeff** (1 in 10 chance). A checksum reduces false positives but can't remove them, which is why context words matter.

**Likely question: "Is 96.5% real-world accuracy?"** No. It's synthetic data, useful for comparing versions. Real text has typos, mixed Hindi-English and odd formats. The next step would be testing on real, anonymised support tickets.

---

## 6. API, UI, tests, Docker

- **API (`api.py`):** FastAPI with Pydantic validation, such as text length limits and session ID format. Interactive docs are at `/docs`.
- **UI (`static/`):** plain HTML, CSS and JavaScript, no framework.
  - An animated **data path** lights up each stage (detect, tokenize, AI model, restore) using real timings returned by the API.
  - **Hover any token** and it lights up in every step, so you can follow one value from your text to the model and back.
  - Live stats, a token **lineage** view (tokenized → restored → erased), and a Gemini-style ambient background with frosted-glass cards.
  - Animations switch off automatically for users who turn on "reduce motion".
  - It calls the API with `fetch()` and draws the results. The privacy logic lives on the server.
  - The highlighting works from the character positions the API returns.
  - It adapts to light and dark mode and works on mobile.
- **Tests (`tests/`):** 41 pytest tests.
  - Checksum maths, Indian names, order IDs being ignored.
  - Encryption at rest: the raw value never appears in the database file.
  - Erasure across sessions, consent, and the API flow.
- **Docker:** a slim Python image running as a non-root user. `docker-compose` keeps the vault on a volume. Keys come from environment variables (`.env.example`).

---

## 7. What to do before an interview

1. Run it: `pip install -r requirements-dev.txt`, then `uvicorn vaultai.api:app --reload`, then open http://localhost:8000.
2. Get a free Gemini key at https://aistudio.google.com/apikey, put it in `.env`, and try a real chat. **The real-Gemini path was written but couldn't be tested here without a key, so test it once yourself.**
3. Run `pytest -q` and `python eval/evaluate.py holdout.jsonl` and read the output.
4. Practise the 30-second pitch, then explain one layer in depth (checksums or the fingerprint are good choices).

## 8. Possible next steps (good answers to "what would you add?")

- An optional LLM second pass for hard cases, run locally.
- Hindi and Hinglish support, plus OCR for ID card images.
- Role-based access, so only authorised staff can restore values.
- A key-rotation plan and a managed secrets store.
- Testing on real, anonymised data.
