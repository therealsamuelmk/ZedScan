package com.microlasan.zedscan;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.microlasan.zedscan.security.SpamClassifier;
import com.microlasan.zedscan.security.SpamClassifier.Result;
import com.microlasan.zedscan.security.SpamClassifier.Rules;

import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Host-side (JVM) accuracy suite for {@link SpamClassifier}, exercising the real
 * shipped {@code assets/spam_rules.json}. No Android device required.
 */
public class SpamClassifierTest {

    private static Rules RULES;

    @BeforeClass
    public static void loadRealRules() throws Exception {
        String[] candidates = {
                "src/main/assets/spam_rules.json",
                "app/src/main/assets/spam_rules.json",
                "../app/src/main/assets/spam_rules.json"
        };
        String json = null;
        for (String c : candidates) {
            File f = new File(c);
            if (f.exists()) {
                json = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
                break;
            }
        }
        assertNotNull("Could not locate spam_rules.json from " + new File(".").getAbsolutePath(), json);
        RULES = SpamClassifier.parseRules(json);
        assertNotNull("spam_rules.json failed to parse", RULES);
    }

    private static Result run(Sample s) {
        return SpamClassifier.classifyWith(RULES, s.sender, s.title, s.body, s.channel);
    }

    // ------------------------------------------------------------------
    // Targeted behavioural assertions
    // ------------------------------------------------------------------

    @Test
    public void prizeScamWithLink_isSpam() {
        Result r = SpamClassifier.classifyWith(RULES, "PROMO-WIN",
                "Congratulations!",
                "CONGRATULATIONS! You have won K50,000 in the MTN promo. Claim your prize now: http://mtn-promo.xyz/claim",
                "SMS");
        assertEquals(r.toString(), "SPAM", r.verdict);
    }

    @Test
    public void spoofedTrustedSenderNameWithPrizeAndLink_stillSpam() {
        // Display name says "MTN" but it is an obvious prize + link scam -> damping must NOT rescue it.
        Result r = SpamClassifier.classifyWith(RULES, "MTN",
                "You won!",
                "You have won a cash prize of K10000. Send airtime of K50 processing fee then click https://bit.ly/mtn-win",
                "SMS");
        assertEquals(r.toString(), "SPAM", r.verdict);
    }

    @Test
    public void genuineOtp_fromShortcode_isSafe() {
        Result r = SpamClassifier.classifyWith(RULES, "Zanaco",
                "Zanaco",
                "Your OTP is 894213. Do not share this code with anyone. Your balance is K1,240.55",
                "SMS");
        assertEquals(r.toString(), "SAFE", r.verdict);
    }

    @Test
    public void genuineDeliveryNotification_isSafe() {
        Result r = SpamClassifier.classifyWith(RULES, "DHL",
                "DHL",
                "Your order has shipped and is out for delivery today. Reference number 7741902.",
                "SMS");
        assertEquals(r.toString(), "SAFE", r.verdict);
    }

    @Test
    public void otpPhishAskingToShareCode_isSpam() {
        Result r = SpamClassifier.classifyWith(RULES, "+2519900112233",
                "Security",
                "Please share your OTP and PIN to verify your account or it will be suspended within 24 hours.",
                "SMS");
        assertEquals(r.toString(), "SPAM", r.verdict);
    }

    @Test
    public void homoglyphBankPhish_isDetected() {
        // 'а','о','с' are Cyrillic look-alikes.
        Result r = SpamClassifier.classifyWith(RULES, "info@secуre-verify.top",
                "Action required",
                "Your а ccоunt is locked. Verify your account here: http://secure-verify.top/login",
                "GMAIL");
        assertEquals(r.toString(), "SPAM", r.verdict);
        assertTrue(r.reasons.toString(), r.reasons.toString().contains("homoglyph"));
    }

    @Test
    public void leetObfuscatedPhish_isNotSafe() {
        Result r = SpamClassifier.classifyWith(RULES, "alerts",
                "Notice",
                "V3rify y0ur acc0unt n0w or it will be susp3nded: http://tinyurl.com/x9",
                "SMS");
        assertEquals("expected SPAM, got " + r, "SPAM", r.verdict);
    }

    @Test
    public void spacedOutKeywords_areDeobfuscated() {
        Result r = SpamClassifier.classifyWith(RULES, "win",
                "Prize",
                "c l a i m   y o u r   p r i z e now at http://rb.gy/win and send K20 fee",
                "SMS");
        assertTrue("expected not SAFE, got " + r, !"SAFE".equals(r.band));
    }

    @Test
    public void plainPersonalMessage_isSafe() {
        Result r = SpamClassifier.classifyWith(RULES, "Mum",
                "Mum",
                "Hi, are we still meeting for lunch tomorrow at 1pm? Let me know.",
                "SMS");
        assertEquals(r.toString(), "SAFE", r.verdict);
        assertEquals(r.toString(), "SAFE", r.band);
    }

    @Test
    public void gmailChannelIsSlightlyStricterThresholdButHamStillSafe() {
        Result r = SpamClassifier.classifyWith(RULES, "newsletter@myshop.com",
                "Your receipt",
                "Thank you for your payment. Your e-receipt and invoice are attached. Statement is ready.",
                "GMAIL");
        assertEquals(r.toString(), "SAFE", r.verdict);
    }

    // ------------------------------------------------------------------
    // Corpus-level precision / recall
    // ------------------------------------------------------------------

    @Test
    public void corpusAccuracyMeetsBar() {
        List<Sample> corpus = corpus();
        int tp = 0, fp = 0, tn = 0, fn = 0;
        List<String> misses = new ArrayList<>();

        for (Sample s : corpus) {
            boolean predSpam = "SPAM".equals(run(s).verdict);
            if (s.spam && predSpam) tp++;
            else if (s.spam) { fn++; misses.add("FN: " + s.title + " -> " + run(s)); }
            else if (predSpam) { fp++; misses.add("FP: " + s.title + " -> " + run(s)); }
            else tn++;
        }

        int n = corpus.size();
        double accuracy = (tp + tn) / (double) n;
        double precision = tp + fp == 0 ? 1 : tp / (double) (tp + fp);
        double recall = tp + fn == 0 ? 1 : tp / (double) (tp + fn);

        System.out.println("=== ZedScan corpus (" + n + " messages) ===");
        System.out.printf("TP=%d FP=%d TN=%d FN=%d%n", tp, fp, tn, fn);
        System.out.printf("accuracy=%.3f precision=%.3f recall=%.3f%n", accuracy, precision, recall);
        for (String m : misses) System.out.println("  " + m);

        assertTrue("accuracy too low: " + accuracy, accuracy >= 0.90);
        assertTrue("precision too low (too many false alarms): " + precision, precision >= 0.90);
        assertTrue("recall too low (missed spam): " + recall, recall >= 0.88);
    }

    // ------------------------------------------------------------------
    // Labelled corpus
    // ------------------------------------------------------------------
    private static final class Sample {
        final String channel, sender, title, body;
        final boolean spam;
        Sample(String channel, String sender, String title, String body, boolean spam) {
            this.channel = channel; this.sender = sender; this.title = title; this.body = body; this.spam = spam;
        }
    }

    private static Sample spam(String ch, String sender, String title, String body) {
        return new Sample(ch, sender, title, body, true);
    }
    private static Sample ham(String ch, String sender, String title, String body) {
        return new Sample(ch, sender, title, body, false);
    }

    private static List<Sample> corpus() {
        List<Sample> c = new ArrayList<>();

        // ---- SPAM: SMS ----
        c.add(spam("SMS", "PRIZEWIN", "Winner", "CONGRATULATIONS! Your number won K85,000 in the Airtel draw. Claim your prize: http://airtel-reward.top/win"));
        c.add(spam("SMS", "+2348012345678", "Loan", "Your loan of K5000 is approved! No collateral. Send K75 processing fee to 0977000111 to receive instantly."));
        c.add(spam("SMS", "Info", "Bank", "Your account has been suspended due to unusual activity. Verify your account now: https://bit.ly/acc-verify"));
        c.add(spam("SMS", "MOMO", "MoMo", "Dear customer, confirm your PIN and OTP to reactivate your wallet or lose access within 24 hours."));
        c.add(spam("SMS", "DELIVERY", "Parcel", "Your parcel could not be delivered. Pay a small customs fee of K35 here: http://track-parcel.click/pay"));
        c.add(spam("SMS", "JOBS", "Hiring", "Work from home and earn K800 per day! No experience needed. WhatsApp us on +260970000000 now."));
        c.add(spam("SMS", "CRYPTO", "Invest", "Double your money in 7 days with our crypto investment. Guaranteed returns. Join: https://t.co/xyz"));
        c.add(spam("SMS", "ZANACO", "Alert", "You have won a cash prize! Send airtime K50 as clearing fee then click https://tinyurl.com/z-win to claim."));
        c.add(spam("SMS", "GIVEAWAY", "FREE", "FREE AIRTIME!!! CLAIM NOW BEFORE IT IS TOO LATE!!! http://free-airtime.xyz"));
        c.add(spam("SMS", "alerts", "Verify", "V3rify y0ur acc0unt immediately: http://rb.gy/9ph1sh or your account will be closed."));
        c.add(spam("SMS", "reward-dept7", "Points", "Your loyalty reward points are about to expire. Redeem now: http://mtn.rewards-zm.online/redeem"));
        c.add(spam("SMS", "+19998887777", "Hello", "I am the beneficiary of an inheritance fund and need your help to transfer the amount. Call us on +19998887777."));
        c.add(spam("SMS", "SECURE", "Locked", "Unauthorized login detected. Confirm your identity here: www.secure-login-verify.info/confirm"));
        c.add(spam("SMS", "PROMO", "Bonus", "You have been selected for a K20,000 gift voucher. Pay refundable fee K100 to 0966123123."));
        c.add(spam("SMS", "BankZM", "Urgent", "URGENT: final notice. Your card will be blocked. Update your details: http://196.15.22.9/bank"));

        // ---- SPAM: Gmail ----
        c.add(spam("GMAIL", "no-reply@paypa1-support.com", "Your account is limited", "We detected unusual activity. Verify your account within 24 hours to avoid suspension: http://paypa1-support.com/verify"));
        c.add(spam("GMAIL", "billing@invoice-docs.top", "Invoice overdue", "Open the attached invoice to avoid penalty. Pay now: https://invoice-docs.top/pay?id=99"));
        c.add(spam("GMAIL", "winner@global-lotto.club", "You WON", "Congratulations you are a winner of USD 1,000,000 in the global lotto. Send processing fee to claim your prize."));
        c.add(spam("GMAIL", "support@amaz0n-security.xyz", "Sign-in blocked", "Your account is locked. Click to verify: http://amaz0n-security.xyz/login and confirm your password."));
        c.add(spam("GMAIL", "hr@remote-careers.online", "Job offer", "You are hired immediately for a work from home role with daily payout. Reply with your bank details."));
        c.add(spam("GMAIL", "info@courier-update.click", "Delivery on hold", "Your shipment is pending. Confirm your delivery and pay customs clearance fee: http://courier-update.click/pay"));
        c.add(spam("GMAIL", "alert@secure-verify.top", "Action required", "Your аccоunt will be closed. Verify your account here: http://secure-verify.top/login"));
        c.add(spam("GMAIL", "promo@bank-rewards.live", "Reward points expiring", "Your bonus points will expire today. Redeem: https://cutt.ly/rewards and pay K10 to release."));

        // ---- HAM: SMS ----
        c.add(ham("SMS", "Zanaco", "Zanaco", "Your OTP is 552310. Do not share this code with anyone."));
        c.add(ham("SMS", "MTN", "MTN", "Your airtime balance is K12.50. Data balance 1.2GB valid until 30/09."));
        c.add(ham("SMS", "AirtelMoney", "Airtel Money", "You have received K300.00 from JOHN BANDA. Your available balance is K812.00. Ref no ABC123."));
        c.add(ham("SMS", "Mum", "Mum", "Hi, are we still meeting for lunch tomorrow at 1pm? Let me know."));
        c.add(ham("SMS", "James", "James", "Thanks for sending the report. I'll review it and call you this afternoon."));
        c.add(ham("SMS", "ZESCO", "ZESCO", "Payment received. Your token is 1234-5678-9012-3456-7890. Units: 210.5 kWh."));
        c.add(ham("SMS", "Clinic", "Clinic", "Reminder: your appointment is on Thursday at 10:00. Please arrive 10 minutes early."));
        c.add(ham("SMS", "FNB", "FNB", "A transaction of K450.00 was made on your card at SHOPRITE. Current balance K3,120.10."));
        c.add(ham("SMS", "DStv", "DStv", "Thank you for your payment of K420. Your subscription is active until 25 October."));
        c.add(ham("SMS", "Zamtel", "Zamtel", "Your verification code is 71829. It expires in 10 minutes."));
        c.add(ham("SMS", "Peter", "Peter", "Meeting moved to 3pm in the boardroom. Bring the printed statement."));
        c.add(ham("SMS", "School", "School", "Dear parent, the term ends on 5 December. Reports will be issued on the last day."));

        // ---- HAM: Gmail ----
        c.add(ham("GMAIL", "receipts@shoprite.co.zm", "Your e-receipt", "Thank you for your payment. Your e-receipt for K235.40 is attached. Reference number 5567."));
        c.add(ham("GMAIL", "no-reply@github.com", "Sign-in from new device", "Your verification code is 771294. If this was you, no action is needed."));
        c.add(ham("GMAIL", "hr@company.co.zm", "Payslip", "Your payslip for September is ready. Net pay has been processed to your account."));
        c.add(ham("GMAIL", "newsletter@techweekly.com", "This week in tech", "Here are the top stories this week. Read more on our site."));
        c.add(ham("GMAIL", "team@project.io", "Notes", "Meeting notes attached. Next sync is Tuesday. Thanks everyone for a productive session."));
        c.add(ham("GMAIL", "billing@aws.amazon.com", "Invoice available", "Your invoice for August is available. Total due USD 42.10. No action needed if on auto-pay."));
        c.add(ham("GMAIL", "support@bank.co.zm", "Statement ready", "Your monthly statement is ready to view in the app. Current balance is shown on the dashboard."));
        c.add(ham("GMAIL", "friend@gmail.com", "Photos", "Sending the holiday photos as promised. Was great catching up last week!"));

        return c;
    }
}
