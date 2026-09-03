package com.microlasan.zedscan.security;

import android.content.Context;
import android.content.res.AssetManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lightweight, JSON-driven spam / phishing classifier for SMS and Gmail notifications.
 *
 * <p>Design goals: no ML, no network, no heavy NLP. All tunables live in
 * {@code assets/spam_rules.json} (schema v2). This class only implements the
 * scoring engine; every weight, keyword, regex and combo is data.</p>
 *
 * <p>Pipeline: normalise text (unicode / homoglyph / zero-width / leet / spacing) →
 * collect named signals (keyword categories, regex hits, URL + sender + obfuscation
 * heuristics) → score categories / regex / ham keywords → apply data-driven combo
 * bonuses → apply trusted-sender damping → band the score (SAFE / SUSPICIOUS / SPAM).</p>
 */
public final class SpamClassifier {

    private SpamClassifier() {}

    // ---------------------------------------------------------------------
    // Fallback used only if the rules file is missing / unparseable.
    // ---------------------------------------------------------------------
    private static final String[] FALLBACK_KEYWORDS = {
            "you have won", "congratulations", "claim your prize", "lottery",
            "urgent", "final notice", "verify your account", "account suspended",
            "send money", "airtime", "deposit", "loan approved", "click", "http", "https"
    };

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://\\S+)|(www\\.[a-z0-9-]+\\.\\S+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern MONEY_PATTERN = Pattern.compile(
            "(k\\s*\\d+)|(\\$\\s*\\d+)|(\\d+\\s*zmw)|(\\d+\\s*kwacha)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ALL_CAPS_LONG = Pattern.compile("^[A-Z0-9\\s\\p{Punct}]{16,}$");
    private static final Pattern REPEAT_RUN = Pattern.compile("([a-z])\\1{2,}");
    private static final Pattern LEET_IN_WORD = Pattern.compile("[a-z][0-9@$][a-z]");
    private static final Pattern ZERO_WIDTH = Pattern.compile("[\\u00AD\\u200B-\\u200F\\u202A-\\u202E\\u2060\\uFEFF]");
    private static final Pattern MULTISPACE = Pattern.compile("\\s+");
    private static final Pattern SINGLE_LETTER_SPACING =
            Pattern.compile("(?<=\\b[a-z0-9])\\s+(?=[a-z0-9]\\b)");

    /** Common Cyrillic / Greek look-alikes mapped to their Latin twin. */
    private static final Map<Character, Character> HOMOGLYPHS = buildHomoglyphs();
    /** Leet substitutions applied to a shadow copy used for keyword matching only. */
    private static final Map<Character, Character> LEET = buildLeet();

    private static volatile Rules RULES = null;

    /** Call once early (e.g. from the NotificationListener). Cheap and idempotent. */
    public static void ensureLoaded(Context context) {
        if (RULES != null) return;
        synchronized (SpamClassifier.class) {
            if (RULES == null) RULES = loadRulesFromAssets(context);
        }
    }

    /** Back-compatible entry point (channel unknown). */
    public static Result classify(String sender, String title, String body) {
        return classify(sender, title, body, null);
    }

    /** @param channel "SMS", "GMAIL" or {@code null}. */
    public static Result classify(String sender, String title, String body, String channel) {
        return classifyWith(RULES, sender, title, body, channel);
    }

    // ---------------------------------------------------------------------
    // Core engine (pure function of rules + inputs -> result). Test-friendly.
    // ---------------------------------------------------------------------
    public static Result classifyWith(Rules rules, String sender, String title, String body, String channel) {
        final String senderRaw = safe(sender);
        final String rawJoined = MULTISPACE.matcher((senderRaw + " \n " + safe(title) + " \n " + safe(body)).trim())
                .replaceAll(" ");
        final Norm norm = normalise(rawJoined);

        final List<String> reasons = new ArrayList<>();
        final Set<String> signals = new HashSet<>();
        int score = 0;

        if (rules == null) {
            return fallbackClassify(norm, title, body);
        }

        final int maxScore = rules.maxScore;

        // --- URL heuristics -------------------------------------------------
        final List<String> urls = extractUrls(norm.canonical);
        if (!urls.isEmpty()) signals.add("sig:url");

        // --- Regex rules --------------------------------------------------
        for (RegexRule rr : rules.regex) {
            if (rr.pattern == null) continue;
            if (rxFind(rr.pattern, norm)) {
                score += rr.w;
                signals.add("rx:" + rr.name);
                reasons.add("regex:" + rr.name + " (+" + rr.w + ")");
                if ("url_shortener".equals(rr.name)) signals.add("sig:shortener");
                if ("money_amount".equals(rr.name)) signals.add("sig:money");
                if ("url_any".equals(rr.name)) signals.add("sig:url");
            }
        }

        // --- Keyword categories (word-boundary aware, obfuscation aware) --
        boolean obfuscatedHitCounted = false;
        for (KeywordCategory cat : rules.keywordCategories) {
            KwHit hit = categoryHit(cat, norm);
            if (hit == KwHit.NONE) continue;
            score += cat.weight;
            signals.add("cat:" + cat.name);
            reasons.add("category:" + cat.name + " (+" + cat.weight + ")");
            if (hit == KwHit.OBFUSCATED && !obfuscatedHitCounted && rules.obf != null) {
                int w = Math.max(rules.obf.spacedKeywordWeight, rules.obf.leetKeywordWeight);
                if (w > 0) {
                    score += w;
                    reasons.add("obfuscated-keyword (+" + w + ")");
                    obfuscatedHitCounted = true;
                }
            }
        }

        // --- Legacy flat "contains" list (still honoured) ----------------
        for (ContainsRule cr : rules.contains) {
            if (cr.p == null || cr.p.isEmpty()) continue;
            if (norm.canonical.contains(cr.p) || norm.squeezed.contains(cr.p)
                    || norm.deSpaced.contains(cr.p)) {
                score += cr.w;
                reasons.add("contains:" + cr.p + " (+" + cr.w + ")");
            }
        }

        // --- Ham keywords (negative weight) -----------------------------
        if (rules.hamKeywords != null && !rules.hamKeywords.terms.isEmpty()) {
            for (Pattern p : rules.hamKeywords.compiled) {
                if (p.matcher(norm.canonical).find() || p.matcher(norm.squeezed).find()) {
                    score += rules.hamKeywords.weight; // negative
                    reasons.add("ham-keyword (" + rules.hamKeywords.weight + ")");
                    break;
                }
            }
        }

        // --- ALL CAPS heuristic ---------------------------------------
        final String rawShout = (safe(title) + " " + safe(body)).trim();
        if (rules.allCapsMinLen > 0 && rawShout.length() >= rules.allCapsMinLen
                && capsRatio(rawShout) >= rules.allCapsRatio
                && ALL_CAPS_LONG.matcher(rawShout).matches()) {
            score += rules.allCapsWeight;
            reasons.add("all-caps (+" + rules.allCapsWeight + ")");
        }

        // --- URL structural heuristics -------------------------------
        if (rules.url != null && !urls.isEmpty()) {
            if (urls.size() >= rules.url.multiUrlThreshold && rules.url.multiUrlWeight > 0) {
                score += rules.url.multiUrlWeight;
                reasons.add("many-urls x" + urls.size() + " (+" + rules.url.multiUrlWeight + ")");
            }
            int maxDepth = 0, maxHostLen = 0;
            for (String u : urls) {
                String host = hostOf(u);
                maxDepth = Math.max(maxDepth, countDots(host));
                maxHostLen = Math.max(maxHostLen, host.length());
            }
            if (rules.url.manySubdomainsThreshold > 0 && maxDepth + 1 >= rules.url.manySubdomainsThreshold
                    && rules.url.manySubdomainsWeight > 0) {
                score += rules.url.manySubdomainsWeight;
                reasons.add("deep-subdomains (+" + rules.url.manySubdomainsWeight + ")");
            }
            if (rules.url.longHostThreshold > 0 && maxHostLen >= rules.url.longHostThreshold
                    && rules.url.longHostWeight > 0) {
                score += rules.url.longHostWeight;
                reasons.add("long-host (+" + rules.url.longHostWeight + ")");
            }
        }

        // --- Obfuscation heuristics ---------------------------------
        if (rules.obf != null) {
            if (norm.hadZeroWidth && rules.obf.zeroWidthWeight > 0) {
                score += rules.obf.zeroWidthWeight;
                reasons.add("zero-width-chars (+" + rules.obf.zeroWidthWeight + ")");
            }
            if (norm.hadHomoglyph && rules.obf.homoglyphWeight > 0) {
                score += rules.obf.homoglyphWeight;
                reasons.add("homoglyph-chars (+" + rules.obf.homoglyphWeight + ")");
            }
            if (rules.obf.leetKeywordWeight > 0 && LEET_IN_WORD.matcher(norm.lower).find()) {
                score += rules.obf.leetKeywordWeight;
                reasons.add("leet-in-word (+" + rules.obf.leetKeywordWeight + ")");
            }
            if (rules.obf.repeatedCharRunWeight > 0 && REPEAT_RUN.matcher(norm.lower).find()) {
                score += rules.obf.repeatedCharRunWeight;
                reasons.add("repeated-char-run (+" + rules.obf.repeatedCharRunWeight + ")");
            }
            if (rules.obf.excessiveEmojiThreshold > 0
                    && emojiCount(rawJoined) >= rules.obf.excessiveEmojiThreshold
                    && rules.obf.excessiveEmojiWeight > 0) {
                score += rules.obf.excessiveEmojiWeight;
                reasons.add("emoji-spam (+" + rules.obf.excessiveEmojiWeight + ")");
            }
        }

        // --- Sender reputation ------------------------------------
        final String senderLower = norm(senderRaw);
        for (Pattern p : rules.senderBlocklistRegex) {
            if (p.matcher(senderLower).find()) {
                score += 22;
                signals.add("sig:sender_blocklist");
                reasons.add("sender-blocklisted (+22)");
                break;
            }
        }
        for (Pattern p : rules.highRiskSenderRegex) {
            if (p.matcher(senderLower).find()) {
                score += 12;
                reasons.add("sender-high-risk (+12)");
                break;
            }
        }
        if (rules.phone != null) {
            int digits = countDigits(senderLower);
            String compact = senderLower.replaceAll("[^0-9+]", "");
            boolean looksNumeric = compact.matches("\\+?\\d{6,15}");
            if (looksNumeric) {
                boolean local = false;
                for (String pre : rules.phone.localPrefixes) {
                    if (compact.startsWith(pre) || compact.startsWith("+" + pre)) { local = true; break; }
                }
                if (!local && rules.phone.foreignNumberWeight > 0) {
                    score += rules.phone.foreignNumberWeight;
                    reasons.add("foreign-number-sender (+" + rules.phone.foreignNumberWeight + ")");
                } else if (digits >= 11 && rules.phone.rawLongNumberWeight > 0) {
                    score += rules.phone.rawLongNumberWeight;
                    reasons.add("raw-number-sender (+" + rules.phone.rawLongNumberWeight + ")");
                }
            }
        }

        // --- Data-driven combo bonuses --------------------------
        for (Combo c : rules.combos) {
            if (signals.containsAll(c.all)) {
                score += c.w;
                reasons.add("combo:" + c.name + " (+" + c.w + ")");
            }
        }

        // --- Content whitelist damping (OTP receipts etc.) ------
        for (String w : rules.whitelistContains) {
            if (!w.isEmpty() && norm.canonical.contains(w)) {
                score -= rules.whitelistScoreReduction;
                reasons.add("whitelist-phrase (-" + rules.whitelistScoreReduction + ")");
                break;
            }
        }

        // --- Trusted sender damping ---------------------------
        final boolean senderTrusted = isTrustedSender(rules, senderRaw);
        final boolean neverTrust = senderTrusted && matchesNeverTrust(rules, norm.canonical);
        final boolean obviousScam = senderTrusted && (
                (signals.contains("cat:prize_scam") && signals.contains("sig:url"))
                        || signals.contains("rx:otp_request")
                        || signals.contains("rx:gmail_lookalike")
                        || norm.hadHomoglyph
                        || signals.contains("sig:sender_blocklist"));
        if (senderTrusted && !neverTrust && !obviousScam) {
            score = Math.max(0, score - rules.trustedSenderScoreReduction);
            score = Math.min(score, rules.trustedOverrideMaxScore);
            reasons.add("trusted-sender-damped (cap " + rules.trustedOverrideMaxScore + ")");
        }

        // --- Band the score ---------------------------------
        score = Math.max(0, Math.min(maxScore, score));
        final int delta = rules.channelThresholdDelta.getOrDefault(
                channel == null ? "" : channel.toUpperCase(Locale.ROOT), 0);
        final int spamAt = rules.threshold + delta;
        final int suspAt = rules.suspiciousThreshold + delta;

        final String band;
        if (score >= spamAt) band = "SPAM";
        else if (score >= suspAt) band = "SUSPICIOUS";
        else band = "SAFE";
        final String verdict = score >= spamAt ? "SPAM" : "SAFE";

        return new Result(score, verdict, band, spamAt, Collections.unmodifiableList(reasons));
    }

    // ---------------------------------------------------------------------
    // Fallback path
    // ---------------------------------------------------------------------
    private static Result fallbackClassify(Norm norm, String title, String body) {
        int score = 0;
        for (String kw : FALLBACK_KEYWORDS) if (norm.canonical.contains(kw)) score += 7;
        if (URL_PATTERN.matcher(norm.canonical).find()) score += 20;
        if (MONEY_PATTERN.matcher(norm.canonical).find()) score += 12;
        String raw = (safe(title) + " " + safe(body)).trim();
        if (raw.length() >= 16 && ALL_CAPS_LONG.matcher(raw).matches()) score += 10;
        score = Math.max(0, Math.min(100, score));
        String verdict = score >= 60 ? "SPAM" : "SAFE";
        String band = score >= 60 ? "SPAM" : (score >= 40 ? "SUSPICIOUS" : "SAFE");
        List<String> r = new ArrayList<>();
        r.add("fallback-rules (spam_rules.json missing/invalid)");
        return new Result(score, verdict, band, 60, Collections.unmodifiableList(r));
    }

    // ---------------------------------------------------------------------
    // Normalisation
    // ---------------------------------------------------------------------
    static Norm normalise(String rawJoined) {
        String lower = rawJoined.toLowerCase(Locale.ROOT);

        String zw = ZERO_WIDTH.matcher(lower).replaceAll("");
        boolean hadZeroWidth = zw.length() != lower.length();

        String nfkc = Normalizer.normalize(zw, Normalizer.Form.NFKC);

        StringBuilder sb = new StringBuilder(nfkc.length());
        boolean hadHomoglyph = false;
        for (int i = 0; i < nfkc.length(); i++) {
            char c = nfkc.charAt(i);
            Character mapped = HOMOGLYPHS.get(c);
            if (mapped != null) { sb.append(mapped); hadHomoglyph = true; }
            else sb.append(c);
        }
        // canonical keeps character runs intact so URL / regex matching is not corrupted
        // (e.g. "www" must survive). Repeated-run collapse lives only in the shadow copies
        // used for keyword matching.
        String canonical = MULTISPACE.matcher(sb.toString()).replaceAll(" ").trim();
        String squeezed = REPEAT_RUN.matcher(canonical).replaceAll("$1");
        String deSpaced = SINGLE_LETTER_SPACING.matcher(squeezed).replaceAll("");

        StringBuilder leet = new StringBuilder(deSpaced.length());
        for (int i = 0; i < deSpaced.length(); i++) {
            char c = deSpaced.charAt(i);
            Character m = LEET.get(c);
            leet.append(m != null ? m : c);
        }

        return new Norm(rawJoined.trim(), lower, canonical, squeezed, deSpaced, leet.toString(),
                hadZeroWidth, hadHomoglyph);
    }

    private enum KwHit { NONE, PLAIN, OBFUSCATED }

    private static KwHit categoryHit(KeywordCategory cat, Norm n) {
        boolean plain = false, obf = false;
        for (int i = 0; i < cat.terms.size(); i++) {
            String term = cat.terms.get(i);
            Pattern bound = cat.compiled == null ? null : cat.compiled.get(i);
            if (matchTerm(term, bound, n.canonical)) { plain = true; break; }
            if (matchTerm(term, bound, n.squeezed)
                    || matchTerm(term, bound, n.deSpaced)
                    || matchTerm(term, bound, n.leet)) obf = true;
        }
        if (plain) return KwHit.PLAIN;
        return obf ? KwHit.OBFUSCATED : KwHit.NONE;
    }

    private static boolean matchTerm(String term, Pattern boundPattern, String haystack) {
        if (boundPattern != null) return boundPattern.matcher(haystack).find();
        return haystack.contains(term);
    }

    private static boolean rxFind(Pattern p, Norm n) {
        if (p.matcher(n.canonical).find()) return true;
        if (!n.deSpaced.equals(n.canonical) && p.matcher(n.deSpaced).find()) return true;
        return false;
    }

    // ---------------------------------------------------------------------
    // Small helpers
    // ---------------------------------------------------------------------
    private static List<String> extractUrls(String text) {
        List<String> out = new ArrayList<>();
        Matcher m = URL_PATTERN.matcher(text);
        while (m.find()) out.add(m.group());
        return out;
    }

    private static String hostOf(String url) {
        String s = url.replaceFirst("(?i)^https?://", "").replaceFirst("(?i)^www\\.", "");
        int cut = s.length();
        for (String d : new String[]{"/", "?", "#", ":", " "}) {
            int idx = s.indexOf(d);
            if (idx >= 0) cut = Math.min(cut, idx);
        }
        return s.substring(0, cut);
    }

    private static int countDots(String s) {
        int c = 0;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) == '.') c++;
        return c;
    }

    private static int countDigits(String s) {
        int c = 0;
        for (int i = 0; i < s.length(); i++) if (Character.isDigit(s.charAt(i))) c++;
        return c;
    }

    private static double capsRatio(String s) {
        int letters = 0, upper = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isLetter(c)) {
                letters++;
                if (Character.isUpperCase(c)) upper++;
            }
        }
        return letters == 0 ? 0d : (double) upper / letters;
    }

    private static int emojiCount(String s) {
        int c = 0;
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            if ((cp >= 0x1F000 && cp <= 0x1FAFF) || (cp >= 0x2600 && cp <= 0x27BF)
                    || cp == 0x2B50 || cp == 0x2B55) c++;
            i += Character.charCount(cp);
        }
        return c;
    }

    private static boolean isTrustedSender(Rules rules, String senderRaw) {
        String sender = norm(senderRaw);
        if (sender.isEmpty()) return false;

        // Exact token match (SMS display names: "MTN", "AirtelMoney", "ZANACO")
        for (String tok : sender.split("[^a-z0-9]+")) {
            if (!tok.isEmpty() && rules.trustedSenderExact.contains(tok)) return true;
        }
        for (String ts : rules.trustedSenderContains) {
            if (!ts.isEmpty() && sender.contains(ts)) return true;
        }
        String domain = extractEmailDomain(sender);
        if (domain != null) {
            for (String d : rules.trustedEmailDomains) {
                if (!d.isEmpty() && (domain.equals(d) || domain.endsWith("." + d))) return true;
            }
        }
        return false;
    }

    private static boolean matchesNeverTrust(Rules rules, String canonical) {
        for (Pattern p : rules.neverTrust) if (p.matcher(canonical).find()) return true;
        return false;
    }

    private static String extractEmailDomain(String senderLower) {
        int at = senderLower.lastIndexOf('@');
        if (at < 0 || at == senderLower.length() - 1) return null;
        String domain = senderLower.substring(at + 1).trim();
        while (!domain.isEmpty() && "]>).,;\"'".indexOf(domain.charAt(domain.length() - 1)) >= 0) {
            domain = domain.substring(0, domain.length() - 1);
        }
        return domain.isEmpty() ? null : domain;
    }

    // ---------------------------------------------------------------------
    // Rules loading / parsing
    // ---------------------------------------------------------------------
    private static Rules loadRulesFromAssets(Context context) {
        try {
            if (context == null) return null;
            AssetManager am = context.getAssets();
            try (InputStream is = am.open("spam_rules.json")) {
                return parseRules(readAll(is));
            }
        } catch (Throwable t) {
            return null;
        }
    }

    /** Parse a rules JSON document. Returns {@code null} on any failure. Package-visible for tests. */
    public static Rules parseRules(String json) {
        try {
            JSONObject root = new JSONObject(json);
            Rules r = new Rules();

            r.threshold = root.optInt("threshold", 55);
            r.suspiciousThreshold = root.optInt("suspiciousThreshold", Math.max(0, r.threshold - 17));
            r.maxScore = root.optInt("maxScore", 100);
            r.allCapsMinLen = root.optInt("allCapsMinLen", 16);
            r.allCapsRatio = root.optDouble("allCapsRatio", 0.7);
            r.allCapsWeight = root.optInt("allCapsWeight", 10);
            r.trustedSenderScoreReduction = root.optInt("trustedSenderScoreReduction", 45);
            r.trustedOverrideMaxScore = root.optInt("trustedOverrideMaxScore", 28);
            r.whitelistScoreReduction = root.optInt("whitelistScoreReduction", 30);

            JSONObject delta = root.optJSONObject("channelThresholdDelta");
            if (delta != null) {
                for (java.util.Iterator<String> it = delta.keys(); it.hasNext(); ) {
                    String k = it.next();
                    r.channelThresholdDelta.put(k.toUpperCase(Locale.ROOT), delta.optInt(k, 0));
                }
            }

            r.trustedSenderExact.addAll(lowerList(root.optJSONArray("trustedSenderExact")));
            r.trustedSenderContains.addAll(lowerList(root.optJSONArray("trustedSenderContains")));
            r.trustedEmailDomains.addAll(lowerList(root.optJSONArray("trustedEmailDomains")));
            r.whitelistContains.addAll(lowerList(root.optJSONArray("whitelistContains")));

            r.neverTrust.addAll(compileList(root.optJSONArray("neverTrustRegex")));
            r.senderBlocklistRegex.addAll(compileList(root.optJSONArray("senderBlocklistRegex")));
            r.highRiskSenderRegex.addAll(compileList(root.optJSONArray("highRiskSenderRegex")));

            JSONArray contains = root.optJSONArray("contains");
            if (contains != null) {
                for (int i = 0; i < contains.length(); i++) {
                    JSONObject o = contains.optJSONObject(i);
                    if (o == null) continue;
                    ContainsRule cr = new ContainsRule();
                    cr.p = optLower(o.optString("p", null));
                    cr.w = o.optInt("w", 0);
                    if (cr.p != null && !cr.p.isEmpty() && cr.w != 0) r.contains.add(cr);
                }
            }

            JSONArray regex = root.optJSONArray("regex");
            if (regex != null) {
                for (int i = 0; i < regex.length(); i++) {
                    JSONObject o = regex.optJSONObject(i);
                    if (o == null) continue;
                    String rx = o.optString("r", null);
                    int w = o.optInt("w", 0);
                    if (rx == null || rx.trim().isEmpty() || w == 0) continue;
                    RegexRule rr = new RegexRule();
                    rr.name = o.optString("name", "rx_" + i);
                    rr.pattern = Pattern.compile(rx, Pattern.CASE_INSENSITIVE);
                    rr.w = w;
                    r.regex.add(rr);
                }
            }

            JSONArray cats = root.optJSONArray("keywordCategories");
            if (cats != null) {
                for (int i = 0; i < cats.length(); i++) {
                    JSONObject o = cats.optJSONObject(i);
                    if (o == null) continue;
                    KeywordCategory kc = new KeywordCategory();
                    kc.name = o.optString("name", "cat_" + i);
                    kc.weight = o.optInt("weight", 10);
                    kc.wordBoundary = o.optBoolean("wordBoundary", false);
                    JSONArray terms = o.optJSONArray("terms");
                    if (terms != null) {
                        for (int j = 0; j < terms.length(); j++) {
                            String t = optLower(terms.optString(j, null));
                            if (t == null || t.isEmpty()) continue;
                            kc.terms.add(t);
                            kc.compiled.add(kc.wordBoundary
                                    ? Pattern.compile("\\b" + Pattern.quote(t) + "\\b")
                                    : null);
                        }
                    }
                    if (!kc.terms.isEmpty()) r.keywordCategories.add(kc);
                }
            }

            JSONObject ham = root.optJSONObject("hamKeywords");
            if (ham != null) {
                HamKeywords hk = new HamKeywords();
                hk.weight = ham.optInt("weight", -14);
                boolean wb = ham.optBoolean("wordBoundary", true);
                JSONArray terms = ham.optJSONArray("terms");
                if (terms != null) {
                    for (int j = 0; j < terms.length(); j++) {
                        String t = optLower(terms.optString(j, null));
                        if (t == null || t.isEmpty()) continue;
                        hk.terms.add(t);
                        hk.compiled.add(wb
                                ? Pattern.compile("\\b" + Pattern.quote(t) + "\\b")
                                : Pattern.compile(Pattern.quote(t)));
                    }
                }
                if (!hk.terms.isEmpty()) r.hamKeywords = hk;
            }

            JSONObject url = root.optJSONObject("urlHeuristics");
            if (url != null) {
                UrlHeuristics u = new UrlHeuristics();
                u.multiUrlThreshold = url.optInt("multiUrlThreshold", 3);
                u.multiUrlWeight = url.optInt("multiUrlWeight", 10);
                u.manySubdomainsThreshold = url.optInt("manySubdomainsThreshold", 4);
                u.manySubdomainsWeight = url.optInt("manySubdomainsWeight", 12);
                u.longHostThreshold = url.optInt("longHostThreshold", 40);
                u.longHostWeight = url.optInt("longHostWeight", 8);
                r.url = u;
            }

            JSONObject phone = root.optJSONObject("phoneSenderHeuristics");
            if (phone != null) {
                PhoneHeuristics p = new PhoneHeuristics();
                p.rawLongNumberWeight = phone.optInt("rawLongNumberWeight", 6);
                p.foreignNumberWeight = phone.optInt("foreignNumberWeight", 12);
                for (String s : lowerList(phone.optJSONArray("localPrefixes"))) {
                    p.localPrefixes.add(s.replaceAll("[^0-9+]", ""));
                }
                if (p.localPrefixes.isEmpty()) Collections.addAll(p.localPrefixes, "09", "07", "260", "+260");
                r.phone = p;
            }

            JSONObject obf = root.optJSONObject("obfuscation");
            if (obf != null) {
                Obfuscation o = new Obfuscation();
                o.zeroWidthWeight = obf.optInt("zeroWidthWeight", 12);
                o.homoglyphWeight = obf.optInt("homoglyphWeight", 14);
                o.spacedKeywordWeight = obf.optInt("spacedKeywordWeight", 8);
                o.leetKeywordWeight = obf.optInt("leetKeywordWeight", 8);
                o.excessiveEmojiThreshold = obf.optInt("excessiveEmojiThreshold", 5);
                o.excessiveEmojiWeight = obf.optInt("excessiveEmojiWeight", 8);
                o.repeatedCharRunWeight = obf.optInt("repeatedCharRunWeight", 4);
                r.obf = o;
            }

            JSONArray combos = root.optJSONArray("combos");
            if (combos != null) {
                for (int i = 0; i < combos.length(); i++) {
                    JSONObject o = combos.optJSONObject(i);
                    if (o == null) continue;
                    Combo c = new Combo();
                    c.name = o.optString("name", "combo_" + i);
                    c.w = o.optInt("w", 0);
                    JSONArray all = o.optJSONArray("all");
                    if (all != null) for (int j = 0; j < all.length(); j++) {
                        String s = all.optString(j, null);
                        if (s != null && !s.trim().isEmpty()) c.all.add(s.trim());
                    }
                    if (c.w != 0 && !c.all.isEmpty()) r.combos.add(c);
                }
            }

            return r;
        } catch (Throwable t) {
            return null;
        }
    }

    private static List<String> lowerList(JSONArray a) {
        List<String> out = new ArrayList<>();
        if (a == null) return out;
        for (int i = 0; i < a.length(); i++) {
            String s = optLower(a.optString(i, null));
            if (s != null && !s.isEmpty()) out.add(s);
        }
        return out;
    }

    private static List<Pattern> compileList(JSONArray a) {
        List<Pattern> out = new ArrayList<>();
        if (a == null) return out;
        for (int i = 0; i < a.length(); i++) {
            String r = a.optString(i, null);
            if (r == null || r.trim().isEmpty()) continue;
            try {
                out.add(Pattern.compile(r, Pattern.CASE_INSENSITIVE));
            } catch (RuntimeException ignored) { /* skip bad pattern, keep app alive */ }
        }
        return out;
    }

    private static String readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        return bos.toString(StandardCharsets.UTF_8.name());
    }

    private static String safe(String x) { return x == null ? "" : x.trim(); }

    private static String norm(String s) {
        return s == null ? "" : s.trim().toLowerCase(Locale.ROOT);
    }

    private static String optLower(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t.toLowerCase(Locale.ROOT);
    }

    private static Map<Character, Character> buildHomoglyphs() {
        Map<Character, Character> m = new HashMap<>();
        // Cyrillic -> Latin
        m.put('а', 'a'); m.put('е', 'e'); m.put('о', 'o'); m.put('р', 'p');
        m.put('с', 'c'); m.put('у', 'y'); m.put('х', 'x'); m.put('і', 'i');
        m.put('ѕ', 's'); m.put('ԁ', 'd'); m.put('к', 'k'); m.put('м', 'm');
        m.put('н', 'h'); m.put('т', 't'); m.put('в', 'b'); m.put('г', 'r');
        m.put('А', 'a'); m.put('Е', 'e'); m.put('О', 'o'); m.put('Р', 'p');
        m.put('С', 'c'); m.put('Х', 'x'); m.put('І', 'i'); m.put('К', 'k');
        m.put('М', 'm'); m.put('Н', 'h'); m.put('Т', 't'); m.put('В', 'b');
        // Greek -> Latin
        m.put('ο', 'o'); m.put('α', 'a'); m.put('ρ', 'p'); m.put('ν', 'v');
        m.put('ε', 'e'); m.put('ι', 'i'); m.put('κ', 'k'); m.put('υ', 'u');
        m.put('Α', 'a'); m.put('Β', 'b'); m.put('Ε', 'e'); m.put('Ο', 'o');
        m.put('Ρ', 'p'); m.put('Τ', 't'); m.put('Η', 'h'); m.put('Κ', 'k');
        return Collections.unmodifiableMap(m);
    }

    private static Map<Character, Character> buildLeet() {
        Map<Character, Character> m = new HashMap<>();
        m.put('0', 'o'); m.put('1', 'i'); m.put('3', 'e'); m.put('4', 'a');
        m.put('5', 's'); m.put('7', 't'); m.put('@', 'a'); m.put('$', 's');
        m.put('8', 'b');
        return Collections.unmodifiableMap(m);
    }

    // ---------------------------------------------------------------------
    // Value / data types
    // ---------------------------------------------------------------------
    static final class Norm {
        final String raw, lower, canonical, squeezed, deSpaced, leet;
        final boolean hadZeroWidth, hadHomoglyph;
        Norm(String raw, String lower, String canonical, String squeezed, String deSpaced, String leet,
             boolean hadZeroWidth, boolean hadHomoglyph) {
            this.raw = raw; this.lower = lower; this.canonical = canonical;
            this.squeezed = squeezed; this.deSpaced = deSpaced; this.leet = leet;
            this.hadZeroWidth = hadZeroWidth; this.hadHomoglyph = hadHomoglyph;
        }
    }

    public static final class Result {
        public final int score;
        /** Back-compatible binary verdict: "SPAM" when {@code score >= threshold}, else "SAFE". */
        public final String verdict;
        /** Three-way band: "SAFE", "SUSPICIOUS" or "SPAM". */
        public final String band;
        /** Effective spam threshold used for this message (after channel adjustment). */
        public final int threshold;
        /** Human-readable trace of every rule that fired. */
        public final List<String> reasons;

        public Result(int score, String verdict, String band, int threshold, List<String> reasons) {
            this.score = score;
            this.verdict = verdict;
            this.band = band;
            this.threshold = threshold;
            this.reasons = reasons;
        }

        @Override public String toString() {
            return "Result{score=" + score + ", verdict=" + verdict + ", band=" + band
                    + ", threshold=" + threshold + ", reasons=" + reasons + "}";
        }
    }

    static final class ContainsRule { String p; int w; }

    static final class RegexRule { String name; Pattern pattern; int w; }

    static final class KeywordCategory {
        String name;
        int weight;
        boolean wordBoundary;
        final List<String> terms = new ArrayList<>();
        final List<Pattern> compiled = new ArrayList<>();
    }

    static final class HamKeywords {
        int weight = -14;
        final List<String> terms = new ArrayList<>();
        final List<Pattern> compiled = new ArrayList<>();
    }

    static final class UrlHeuristics {
        int multiUrlThreshold, multiUrlWeight;
        int manySubdomainsThreshold, manySubdomainsWeight;
        int longHostThreshold, longHostWeight;
    }

    static final class PhoneHeuristics {
        int rawLongNumberWeight, foreignNumberWeight;
        final List<String> localPrefixes = new ArrayList<>();
    }

    static final class Obfuscation {
        int zeroWidthWeight, homoglyphWeight, spacedKeywordWeight, leetKeywordWeight;
        int excessiveEmojiThreshold, excessiveEmojiWeight, repeatedCharRunWeight;
    }

    static final class Combo {
        String name;
        int w;
        final List<String> all = new ArrayList<>();
    }

    public static final class Rules {
        int threshold = 55;
        int suspiciousThreshold = 38;
        int maxScore = 100;
        int allCapsMinLen = 16;
        double allCapsRatio = 0.7;
        int allCapsWeight = 10;
        int trustedSenderScoreReduction = 45;
        int trustedOverrideMaxScore = 28;
        int whitelistScoreReduction = 30;

        final Map<String, Integer> channelThresholdDelta = new HashMap<>();
        final Set<String> trustedSenderExact = new HashSet<>();
        final List<String> trustedSenderContains = new ArrayList<>();
        final List<String> trustedEmailDomains = new ArrayList<>();
        final List<String> whitelistContains = new ArrayList<>();

        final List<Pattern> neverTrust = new ArrayList<>();
        final List<Pattern> senderBlocklistRegex = new ArrayList<>();
        final List<Pattern> highRiskSenderRegex = new ArrayList<>();

        final List<ContainsRule> contains = new ArrayList<>();
        final List<RegexRule> regex = new ArrayList<>();
        final List<KeywordCategory> keywordCategories = new ArrayList<>();
        HamKeywords hamKeywords;

        UrlHeuristics url;
        PhoneHeuristics phone;
        Obfuscation obf;
        final List<Combo> combos = new ArrayList<>();
    }
}
