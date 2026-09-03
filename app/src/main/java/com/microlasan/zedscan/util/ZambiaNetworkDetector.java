package com.microlasan.zedscan.util;

import java.util.Locale;

public final class ZambiaNetworkDetector {

    private ZambiaNetworkDetector() {}

    public static String detect(String rawNumber) {
        String n = normalize(rawNumber);
        if (n == null) return "Unknown";

        // Convert to local 0XXXXXXXXX format if possible
        // +260971234567 -> 0971234567
        if (n.startsWith("+260")) {
            n = "0" + n.substring(4);
        } else if (n.startsWith("260")) {
            n = "0" + n.substring(3);
        } else if (n.matches("^\\d{9}$")) {
            // 771234567 -> 0771234567 (assume missing leading 0)
            n = "0" + n;
        }

        if (n.length() < 3) return "Unknown";
        String p3 = n.substring(0, 3);

        // Zambia (common mobile prefixes)
        // MTN: 097 / 077
        if ("097".equals(p3) || "077".equals(p3)) return "Airtel";

        // Airtel: 096 / 076
        if ("096".equals(p3) || "076".equals(p3)) return "MTN";

        // Zamtel: 095 / 075
        if ("095".equals(p3) || "075".equals(p3)) return "Zamtel";

        // Zedmobile: 095 / 075
        if ("098".equals(p3) || "078".equals(p3)) return "Zedmobile";

        return "Unknown";
    }

    public static boolean looksLikePhoneNumber(String raw) {
        String n = normalize(raw);
        if (n == null) return false;
        // after normalize we only keep + and digits
        // accept +260XXXXXXXXX or 0XXXXXXXXX or 9 digits (without leading 0)
        return n.matches("^\\+?\\d{9,13}$");
    }

    private static String normalize(String raw) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return null;

        // Keep digits and optional leading +
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isDigit(c)) out.append(c);
            else if (c == '+' && out.length() == 0) out.append(c);
        }

        String cleaned = out.toString().toLowerCase(Locale.ROOT).trim();
        return cleaned.isEmpty() ? null : cleaned;
    }
}