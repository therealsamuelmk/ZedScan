# ZedScan — Spam / Phishing Detection Upgrade

**Date:** 2026-09-03
**Scope:** `SpamClassifier` engine + `assets/spam_rules.json` (schema v1 → v2) + host-side test suite
**Constraint honoured:** still 100 % offline, no ML, no extra runtime dependencies — every
tunable lives in a single JSON file that ships in `assets/`.

---

## 1. Why the old version was inaccurate

| # | Problem in v1 | Effect |
|---|---------------|--------|
| 1 | Detection logic was **half in Java, half in JSON**. Keyword buckets (`PRIZE_WORDS`, `PHISH_WORDS`, `URGENCY_WORDS`), combo bonuses and weights were hard-coded and could not be tuned without a rebuild. | Rules file gave a false sense of configurability. |
| 2 | **Substring matching only** (`joined.contains("winner")`). | `"winner"` fires inside `"spinner"`, `"deposit"` inside `"deposition"` → false positives; and any spacing/punctuation between letters defeated a match → false negatives. |
| 3 | **No text normalisation.** | `"V3rify y0ur acc0unt"`, `"c l a i m   y o u r   p r i z e"`, zero-width joiners and Cyrillic/Greek homoglyphs (`раyраl`) all sailed through. |
| 4 | **No URL structure analysis.** A raw-IP link, an `@`-in-authority link, punycode, a `.xyz`/`.top` throwaway TLD and a legitimate `bit.ly` were all "just a URL". | Weak phishing signal. |
| 5 | **No sender reputation.** A message from `+2519900112233` or `billing@invoice-docs.top` scored the same as one from a bank short-code. | Missed the single strongest real-world signal. |
| 6 | **No "ham" (legitimate) signals.** Only a 3-item OTP whitelist. Bank balance alerts, receipts, delivery updates and OTPs had nothing pulling their score **down**. | Genuine transactional SMS sat close to the threshold. |
| 7 | **Binary output only** (`SPAM` / `SAFE`) with a single global threshold of 60, identical for SMS and Gmail. | No "review this" middle band; Gmail (longer, more marketing text) needs a slightly higher bar. |
| 8 | **Spoof-proofing was ad-hoc** — one hard-coded `hasPrize && hasUrl && hasMoney` check. | Trusted-sender damping could still rescue an obvious scam whose display name was set to `"MTN"`. |
| 9 | **Not testable off-device.** `classify()` depended on a loaded singleton; rule parsing needed an Android `Context`. | No regression net. |

---

## 2. What changed

### 2.1 Engine (`SpamClassifier.java`)

**Everything is now data-driven.** The Java file contains only the scoring *engine*; there
are no hard-coded keywords, weights or combos left.

New pipeline:

```
raw(sender+title+body)
  → normalise()                     (see 2.3)
  → collect named SIGNALS           cat:<category>, rx:<regex>, sig:url / sig:shortener / sig:money,
                                    sig:sender_blocklist
  → score:  keyword categories  (word-boundary aware)
            regex rules
            ham keywords         (negative)
            ALL-CAPS heuristic   (length + uppercase-ratio gate)
            URL structure        (count, sub-domain depth, host length)
            obfuscation          (zero-width, homoglyph, leet-in-word, repeated runs, emoji flood)
            sender reputation    (blocklist / high-risk / foreign-number)
  → data-driven COMBO bonuses    ("all of these signals present → +N")
  → whitelist damping            (OTP / receipt phrases)
  → trusted-sender damping       (unless neverTrust OR obvious-scam signals present)
  → clamp, apply channel threshold delta, band
```

New public surface (backwards compatible):

| Method | Purpose |
|--------|---------|
| `classify(sender, title, body)` | unchanged signature, delegates with `channel = null` |
| `classify(sender, title, body, channel)` | `channel` = `"SMS"` / `"GMAIL"` → threshold delta |
| `classifyWith(Rules, …)` | **pure function**, no global state — used by tests |
| `parseRules(String json)` | parse without an Android `Context` — used by tests |
| `Result.band` | `"SAFE"` / `"SUSPICIOUS"` / `"SPAM"` |
| `Result.reasons` | ordered, human-readable trace of every rule that fired (also logged by the listener) |
| `Result.threshold` | effective spam threshold after channel adjustment |

`Result.verdict` is still the binary `"SPAM"` / `"SAFE"` string, so `DashboardFragment`,
`SpamHistoryAdapter` and the DB schema are untouched — no Room migration.

### 2.2 `ZedScanNotificationListener`

One line: passes the already-known `source` (`"SMS"` / `"GMAIL"`) into `classify(...)` and
logs `score / verdict / band / reasons` under the `ZEDSCAN` tag for field debugging.

### 2.3 Normalisation (the biggest accuracy lever)

| Step | Defeats |
|------|---------|
| Unicode NFKC fold | full-width / styled letters |
| Zero-width / bidi strip (`U+00AD`, `U+200B–200F`, `U+202A–202E`, `U+2060`, `U+FEFF`) | `v‌e‌r‌i‌f‌y` |
| Homoglyph map (Cyrillic + Greek → Latin) | `раypаl`, `secуre` — also raises a scored `homoglyph` flag |
| Repeated-run squeeze (`freeee → free`) on a **shadow copy only** | `"clai­mmm your priiize"` — kept off `canonical` so `www.` / URLs survive |
| Single-letter de-spacing | `c l a i m   y o u r   p r i z e` |
| Leet fold on a shadow copy (`0→o 1→i 3→e 4→a 5→s 7→t @→a $→s 8→b`) | `V3rify y0ur acc0unt` |

Keyword categories are matched against `canonical` **and** the squeezed / de-spaced / leet
shadows; a hit that only lands on a shadow additionally scores an `obfuscated-keyword` bonus.
Regex and URL extraction run on `canonical` (unsqueezed) so link structure is intact.

### 2.4 Rules file (`spam_rules.json`, schema v2)

New parameter groups (all optional, safe defaults in the parser):

| Key | What it adds |
|-----|--------------|
| `suspiciousThreshold` | lower bound of the new middle band |
| `channelThresholdDelta` | `{ "SMS": 0, "GMAIL": 6 }` — per-channel strictness |
| `allCapsRatio` | uppercase-letter ratio gate so long normal text isn't punished |
| `trustedSenderExact` | exact display-name tokens (`mtn`, `zanaco`, `airtelmoney`, …) — no more substring trust |
| `senderBlocklistRegex` | throwaway TLDs, look-alike mail hosts, `prize-dept7`-style names → **+22** |
| `highRiskSenderRegex` | `verify-support@…`, bare international number senders → **+12** |
| `keywordCategories[]` | 9 named, individually-weighted buckets with a `wordBoundary` flag: `credential_phish`, `prize_scam`, `money_request`, `loan_bait`, `urgency`, `delivery_courier`, `crypto_invest`, `job_scam`, `romance_advance_fee` |
| `hamKeywords` | ~30 legitimate-transaction phrases, **negative** weight (OTP, balance, receipt, appointment, statement, …) |
| `regex[]` (rewritten, now `name`d) | raw-IP URL, `@`-authority URL, punycode URL, suspicious-TLD URL, shortener list (12), Gmail look-alike domain, `otp_request` ("confirm/verify/enter your PIN/OTP"), `bank_detail_request`, `earnings_bait` ("earn K800 per day"), `phone_callback`, `attachment_bait`, spaced-letters, excess-punctuation, reward-points-expiry, generic-greeting |
| `urlHeuristics` | multi-URL, deep-subdomain, long-host thresholds + weights |
| `phoneSenderHeuristics` | foreign-number weight + local prefixes (`09`, `07`, `260`) |
| `obfuscation` | per-signal weights (zero-width, homoglyph, leet, repeated-run, emoji flood) |
| `combos[]` | **15 data-driven** "signal set → bonus" rules, e.g. `["cat:prize_scam","sig:url"] → +22`, `["cat:credential_phish","sig:url"] → +18`, `["rx:url_shortener","rx:money_amount"] → +16` |
| `whitelistScoreReduction` | was hard-coded `30`, now tunable |

Legacy v1 keys (`threshold`, `contains[]`, old `regex` `{r,w}` form, `neverTrustRegex`,
`trustedSenderContains`, `trustedEmailDomains`, `whitelistContains`) are still parsed and
honoured — a v1 file keeps working.

### 2.5 Spoof resistance

Trusted-sender damping is now **skipped** when the display name looks trusted *but* any of
these hold: a `neverTrustRegex` hit, `prize_scam + url`, an `otp_request` hit, a Gmail
look-alike domain, a homoglyph flag, or a sender-blocklist hit. So a message with
`sender = "MTN"` and body *"you won K10000, send K50 fee, click bit.ly/…"* is still `SPAM`.

---

## 3. Testing

### 3.1 How to run

```bash
JAVA_HOME=/path/to/jdk-17-or-21 ./gradlew :app:testDebugUnitTest
```

Runs on the JVM — **no emulator/device needed**. `org.json:json` is added as a
`testImplementation` only (the `android.jar` used for unit tests ships non-functional
`org.json` stubs); it is **not** in the app's runtime classpath.

### 3.2 Suite — `app/src/test/java/.../SpamClassifierTest.java`

Loads the **real shipped `assets/spam_rules.json`** (not a fixture) via `parseRules`.

**11 targeted behaviour tests** — all green:

| Test | Asserts |
|------|---------|
| `prizeScamWithLink_isSpam` | classic prize + throwaway-TLD link |
| `spoofedTrustedSenderNameWithPrizeAndLink_stillSpam` | display name `"MTN"` does **not** rescue an obvious scam |
| `genuineOtp_fromShortcode_isSafe` | real OTP + balance from `Zanaco` stays SAFE |
| `genuineDeliveryNotification_isSafe` | real "out for delivery" stays SAFE |
| `otpPhishAskingToShareCode_isSpam` | "share your OTP and PIN … suspended in 24h" |
| `homoglyphBankPhish_isDetected` | Cyrillic `аccоunt` phish → SPAM, `homoglyph` in reasons |
| `leetObfuscatedPhish_isNotSafe` | `V3rify y0ur acc0unt` → SPAM |
| `spacedOutKeywords_areDeobfuscated` | `c l a i m   y o u r   p r i z e` → not SAFE |
| `plainPersonalMessage_isSafe` | "lunch tomorrow at 1pm" → SAFE / band SAFE |
| `gmailChannelIsSlightlyStricterThresholdButHamStillSafe` | receipt e-mail stays SAFE under the higher Gmail bar |

**1 corpus test** — 43 hand-labelled messages (23 spam / 20 ham), SMS + Gmail, including
adventure-fee, crypto, courier, loan, job, homoglyph and leet variants on the spam side and
bank alerts, OTPs, receipts, ZESCO tokens, personal chat and newsletters on the ham side.

```
=== ZedScan corpus (43 messages) ===
TP=23  FP=0  TN=20  FN=0
accuracy=1.000  precision=1.000  recall=1.000
```

Enforced regression floors (headroom for future rule edits):
`accuracy ≥ 0.90`, `precision ≥ 0.90`, `recall ≥ 0.88`.

> Note: this corpus was authored alongside the rules, so 1.000 reflects **fit + no
> regressions**, not a blind benchmark. Its job is to (a) lock in the behaviours above and
> (b) fail loudly if a rule change reintroduces a false positive on realistic transactional
> traffic. Extend `corpus()` with real anonymised samples as they are collected.

### 3.3 Build verification

| Command | Result |
|---------|--------|
| `./gradlew :app:testDebugUnitTest` | **BUILD SUCCESSFUL** — 12 tests, 0 failures |
| `./gradlew :app:assembleDebug` | **BUILD SUCCESSFUL** — APK links & dexes |

Toolchain used: Gradle 8.13, AGP 8.13.2, JDK 21 (JBR). `compileSdk 36`, `minSdk 24`.

---

## 4. Before / after on representative messages

| Message (sender) | v1 | v2 |
|---|---|---|
| `MTN` — "you won K10000, send K50 fee, click bit.ly/mtn-win" | SAFE (trusted-name damping) | **SPAM** (spoof guard) |
| `alerts` — "V3rify y0ur acc0unt n0w … tinyurl.com/x9" | SAFE (leet defeats `contains`) | **SPAM** (leet fold + shortener + combo) |
| `info@secуre-verify.top` — Cyrillic "аccоunt locked … /login" | SAFE (homoglyph + no TLD signal) | **SPAM** (homoglyph +14, suspicious TLD +16, phish+link combo) |
| `MoMo` — "confirm your PIN and OTP to reactivate … 24 hours" | SAFE (score ~34) | **SPAM** (`otp_request` now covers "confirm", +urgency combo) |
| `+2348012345678` — "loan approved, send K75 processing fee" | borderline | **SPAM** (loan_bait + money_request + foreign-number) |
| `Zanaco` — "Your OTP is 894213 … balance K1,240.55" | SAFE | SAFE (ham keywords −14, whitelist −30, trusted) |
| `DHL` — "out for delivery today, ref 7741902" | ~SAFE (close) | SAFE (ham keywords pull well clear) |

---

## 5. Tuning guide (no rebuild)

Edit `app/src/main/assets/spam_rules.json`:

- **Too many false alarms** → raise `threshold` / `channelThresholdDelta`, lower a
  `keywordCategories[].weight`, or add the offending legit phrase to `hamKeywords.terms`.
- **Missing a scam family** → add a `keywordCategories` entry (set `wordBoundary:true` for
  short/ambiguous terms) and, if it only bites in combination, a `combos` rule referencing
  `cat:<name>` / `rx:<name>` / `sig:url|shortener|money`.
- **New trusted bank/short-code** → add the lower-case token to `trustedSenderExact` and the
  mail domain to `trustedEmailDomains`.
- **New shortener / throwaway TLD** → extend the `url_shortener` regex or
  `senderBlocklistRegex`.

A malformed JSON never crashes the app: `parseRules` returns `null` and the engine falls
back to the built-in keyword list.
