package com.microlasan.zedscan.service;

import android.Manifest;
import android.app.Notification;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;
import android.telephony.CellIdentityGsm;
import android.telephony.CellIdentityLte;
import android.telephony.CellIdentityWcdma;
import android.telephony.CellInfo;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoLte;
import android.telephony.CellInfoWcdma;
import android.telephony.TelephonyManager;
import android.util.Log;

import androidx.core.content.ContextCompat;

import com.microlasan.zedscan.data.SpamStore;
import com.microlasan.zedscan.data.db.SpamEventEntity;
import com.microlasan.zedscan.security.SpamClassifier;
import com.microlasan.zedscan.util.ZambiaNetworkDetector;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class ZedScanNotificationListener extends NotificationListenerService {

    private static final String TAG = "ZEDSCAN";
    private static final boolean BLOCK_SPAM_NOTIFICATIONS = false;

    private static final String PKG_GMAIL = "com.google.android.gm";

    private static final Set<String> SMS_PACKAGES = new HashSet<>(Arrays.asList(
            "com.google.android.apps.messaging",
            "com.android.messaging",
            "com.samsung.android.messaging",
            "com.miui.smsextra",
            "com.huawei.mms",
            "com.android.mms",
            "com.android.mms.service"
    ));

    private static String lastKey = null;
    private static long lastKeyAt = 0;

    @Override
    public void onListenerConnected() {
        super.onListenerConnected();
        Log.i(TAG, "NotificationListener connected.");
    }

    @Override
    public void onListenerDisconnected() {
        super.onListenerDisconnected();
        Log.w(TAG, "NotificationListener disconnected.");
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        try {
            if (sbn == null) return;

            Notification n = sbn.getNotification();
            if (n == null) return;

            Bundle extras = n.extras;
            if (extras == null) return;

            String pkg = sbn.getPackageName();
            if (pkg == null) return;

            if ((n.flags & Notification.FLAG_ONGOING_EVENT) != 0) return;

            // Determine source
            String source = null;
            if (PKG_GMAIL.equals(pkg)) source = "GMAIL";
            else if (SMS_PACKAGES.contains(pkg)) source = "SMS";
            if (source == null) return;

            // Extract content
            String title = cs(extras.getCharSequence(Notification.EXTRA_TITLE));
            String text = cs(extras.getCharSequence(Notification.EXTRA_TEXT));
            String bigText = cs(extras.getCharSequence(Notification.EXTRA_BIG_TEXT));
            String subText = cs(extras.getCharSequence(Notification.EXTRA_SUB_TEXT));
            String summaryText = cs(extras.getCharSequence(Notification.EXTRA_SUMMARY_TEXT));

            CharSequence[] lines = extras.getCharSequenceArray(Notification.EXTRA_TEXT_LINES);
            String linesJoined = joinLines(lines);

            String body = firstNonEmpty(bigText, text, linesJoined, subText, summaryText);

            if (isEmpty(title) && isEmpty(body)) return;

            // Sender extraction
            String sender = !isEmpty(title) ? title : "Unknown";
            if ("SMS".equals(source) && !isEmpty(subText) && ZambiaNetworkDetector.looksLikePhoneNumber(subText)) {
                sender = subText;
            }

            // Dedupe
            String key = source + "|" + pkg + "|" + sender + "|" + safe(body);
            long now = System.currentTimeMillis();
            if (key.equals(lastKey) && (now - lastKeyAt) < 4000) return;
            lastKey = key;
            lastKeyAt = now;

            SpamClassifier.ensureLoaded(getApplicationContext());
            SpamClassifier.Result r = SpamClassifier.classify(sender, title, body, source);
            Log.d(TAG, "CLASSIFY score=" + r.score + " verdict=" + r.verdict
                    + " band=" + r.band + " reasons=" + r.reasons);

            // --- Intelligence capture (device context at receipt time) ---
            String networkName = getNetworkNameSafe();
            Integer cellId = getCellIdSafe(); // CID/CI (best effort)
            Location loc = getBestLastKnownLocationSafe();

            Double lat = null, lng = null;
            Float acc = null;

            if (loc != null) {
                lat = loc.getLatitude();
                lng = loc.getLongitude();
                acc = loc.getAccuracy();
            }

            Log.d(TAG, "INTEL network=" + safe(networkName)
                    + " cellId=" + (cellId == null ? "null" : cellId)
                    + " loc=" + (lat == null ? "null" : (lat + "," + lng))
                    + " acc=" + (acc == null ? "null" : acc));

            // Store
            SpamEventEntity e = new SpamEventEntity(
                    source,
                    sender,
                    title,
                    body,
                    now,
                    r.score,
                    r.verdict,
                    networkName,
                    cellId,
                    lat,
                    lng,
                    acc
            );

            SpamStore.insert(getApplicationContext(), e);

            if (BLOCK_SPAM_NOTIFICATIONS && "SPAM".equals(r.verdict)) {
                cancelNotification(sbn.getKey());
            }

        } catch (Throwable t) {
            Log.e(TAG, "onNotificationPosted crashed: " + t.getMessage(), t);
        }
    }

    private String getNetworkNameSafe() {
        try {
            TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
            if (tm == null) return null;
            String name = tm.getNetworkOperatorName();
            return (name == null || name.trim().isEmpty()) ? null : name.trim();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private Integer getCellIdSafe() {
        boolean hasCoarse = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;
        boolean hasFine = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;

        if (!hasCoarse && !hasFine) {
            Log.w(TAG, "INTEL: missing location permission -> cannot read cell tower");
            return null;
        }

        try {
            TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
            if (tm == null) return null;

            // Prefer registered cell
            for (CellInfo info : tm.getAllCellInfo()) {
                if (info == null || !info.isRegistered()) continue;
                Integer cid = extractCid(info);
                if (cid != null && cid > 0) return cid;
            }

            // Fallback
            for (CellInfo info : tm.getAllCellInfo()) {
                Integer cid = extractCid(info);
                if (cid != null && cid > 0) return cid;
            }

            Log.w(TAG, "INTEL: getAllCellInfo() returned none/empty (often means Location is OFF on device)");
            return null;

        } catch (SecurityException se) {
            Log.w(TAG, "INTEL: SecurityException reading cell info (permission/device restriction)");
            return null;
        } catch (Throwable t) {
            Log.w(TAG, "INTEL: failed reading cell info: " + t.getMessage());
            return null;
        }
    }

    private Integer extractCid(CellInfo info) {
        try {
            if (info instanceof CellInfoLte) {
                CellIdentityLte id = ((CellInfoLte) info).getCellIdentity();
                int ci = id.getCi();
                return (ci > 0) ? ci : null;
            }
            if (info instanceof CellInfoGsm) {
                CellIdentityGsm id = ((CellInfoGsm) info).getCellIdentity();
                int cid = id.getCid();
                return (cid > 0) ? cid : null;
            }
            if (info instanceof CellInfoWcdma) {
                CellIdentityWcdma id = ((CellInfoWcdma) info).getCellIdentity();
                int cid = id.getCid();
                return (cid > 0) ? cid : null;
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private Location getBestLastKnownLocationSafe() {
        boolean hasCoarse = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;
        boolean hasFine = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;

        if (!hasCoarse && !hasFine) {
            Log.w(TAG, "INTEL: missing location permission -> cannot read last known location");
            return null;
        }

        try {
            LocationManager lm = (LocationManager) getSystemService(LOCATION_SERVICE);
            if (lm == null) return null;

            Location best = null;

            // Prefer GPS if fine permission
            if (hasFine) {
                best = pickBetter(best, lm.getLastKnownLocation(LocationManager.GPS_PROVIDER));
            }

            // Network provider (often available)
            best = pickBetter(best, lm.getLastKnownLocation(LocationManager.NETWORK_PROVIDER));

            // Passive provider
            best = pickBetter(best, lm.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER));

            if (best == null) {
                Log.w(TAG, "INTEL: lastKnownLocation is null (try enabling Location + open Maps once)");
            }

            return best;

        } catch (SecurityException se) {
            Log.w(TAG, "INTEL: SecurityException reading location");
            return null;
        } catch (Throwable t) {
            Log.w(TAG, "INTEL: failed reading location: " + t.getMessage());
            return null;
        }
    }

    private Location pickBetter(Location a, Location b) {
        if (b == null) return a;
        if (a == null) return b;

        // Prefer newer, then better accuracy
        if (b.getTime() > a.getTime()) return b;
        if (b.getAccuracy() < a.getAccuracy()) return b;
        return a;
    }

    private static String cs(CharSequence x) {
        if (x == null) return null;
        String s = x.toString().trim();
        return s.isEmpty() ? null : s;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static boolean isEmpty(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String firstNonEmpty(String... vals) {
        if (vals == null) return null;
        for (String v : vals) {
            if (v != null && !v.trim().isEmpty()) return v;
        }
        return null;
    }

    private static String joinLines(CharSequence[] lines) {
        if (lines == null || lines.length == 0) return null;
        StringBuilder sb = new StringBuilder();
        for (CharSequence c : lines) {
            if (c == null) continue;
            String s = c.toString().trim();
            if (s.isEmpty()) continue;
            if (sb.length() > 0) sb.append("\n");
            sb.append(s);
        }
        String out = sb.toString().trim();
        return out.isEmpty() ? null : out;
    }
}