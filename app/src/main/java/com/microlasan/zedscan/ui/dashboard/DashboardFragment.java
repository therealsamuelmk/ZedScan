package com.microlasan.zedscan.ui.dashboard;

import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.github.mikephil.charting.data.PieData;
import com.github.mikephil.charting.data.PieDataSet;
import com.github.mikephil.charting.data.PieEntry;
import com.microlasan.zedscan.data.db.SpamEventDao;
import com.microlasan.zedscan.data.db.SpamEventEntity;
import com.microlasan.zedscan.data.db.ZedScanDb;
import com.microlasan.zedscan.databinding.FragmentDashboardBinding;
import com.microlasan.zedscan.service.ZedScanNotificationListener;
import com.microlasan.zedscan.util.NotificationAccess;
import com.microlasan.zedscan.util.ZambiaNetworkDetector;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DashboardFragment extends Fragment {

    private SpamEventDao dao;
    private FragmentDashboardBinding binding;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        binding = FragmentDashboardBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        binding.btnEnableProtection.setOnClickListener(v -> {
            Intent intent = new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
            startActivity(intent);
        });

        refreshProtectionUi();

        dao = ZedScanDb.get(requireContext()).spamEventDao();

        // ✅ Single source of truth: observe all events and compute stats locally
        bindStatsFromAllEvents();
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshProtectionUi();
    }

    private void refreshProtectionUi() {
        if (getContext() == null || binding == null) return;

        boolean enabled = NotificationAccess.isNotificationListenerEnabled(
                requireContext(),
                ZedScanNotificationListener.class
        );

        if (enabled) {
            binding.txtProtectionStatus.setText("Enabled : ZedScan is actively monitoring notifications.");
            binding.btnEnableProtection.setText("Protection Enabled");
            binding.btnEnableProtection.setEnabled(false);
            binding.btnEnableProtection.setAlpha(0.7f);
        } else {
            binding.txtProtectionStatus.setText("Disabled: enable Notification Access to start protection.");
            binding.btnEnableProtection.setText("Enable Protection");
            binding.btnEnableProtection.setEnabled(true);
            binding.btnEnableProtection.setAlpha(1f);
        }
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }

    /**
     * Computes all stats from dao.observeAll()
     * This avoids fragile COUNT queries that depend on exact verdict/source strings.
     */
    private void bindStatsFromAllEvents() {
        if (binding == null) return;

        dao.observeAll().observe(getViewLifecycleOwner(), events -> {
            if (binding == null) return;

            int totalSpam = 0;
            int smsSpam = 0;
            int gmailSpam = 0;

            // top senders map
            Map<String, Integer> senderSpamCounts = new HashMap<>();

            if (events != null) {
                for (SpamEventEntity e : events) {
                    if (e == null) continue;

                    boolean isSpam = isSpamVerdict(e.verdict);
                    if (!isSpam) continue;

                    totalSpam++;

                    String src = safeUpper(e.source);
                    if ("SMS".equals(src)) smsSpam++;
                    else if ("GMAIL".equals(src)) gmailSpam++;

                    String sender = (e.sender != null && !e.sender.trim().isEmpty()) ? e.sender.trim() : "Unknown";
                    senderSpamCounts.put(sender, senderSpamCounts.getOrDefault(sender, 0) + 1);
                }
            }

            // Update stats text
            binding.txtTotalSpam.setText("Total: " + totalSpam);
            binding.txtSmsSpam.setText("SMS: " + smsSpam);
            binding.txtGmailSpam.setText("Mail: " + gmailSpam);

            // Update pie chart
            renderPieFromCounts(smsSpam, gmailSpam);

            // Update top senders if the view exists in layout
            TextView txtTopSenders = findOptionalTopSendersView();
            if (txtTopSenders != null) {
                txtTopSenders.setText(buildTopSendersText(senderSpamCounts, 5));
            }
        });
    }

    private void renderPieFromCounts(int sms, int gmail) {
        if (binding == null) return;

        ArrayList<PieEntry> entries = new ArrayList<>();
        if (sms > 0) entries.add(new PieEntry(sms, "SMS"));
        if (gmail > 0) entries.add(new PieEntry(gmail, "Gmail"));
        if (entries.isEmpty()) entries.add(new PieEntry(1f, "No spam yet"));

        PieDataSet set = new PieDataSet(entries, "");
        set.setSliceSpace(2f);
        set.setValueTextSize(12f);

        PieData data = new PieData(set);

        binding.pieChart.setData(data);
        binding.pieChart.getDescription().setEnabled(false);
        binding.pieChart.setCenterText("Spam Sources");
        binding.pieChart.setHoleRadius(55f);
        binding.pieChart.setTransparentCircleRadius(58f);
        binding.pieChart.invalidate();
    }

    /**
     * If txtTopSenders doesn't exist in your XML, dashboard will still work.
     */
    private TextView findOptionalTopSendersView() {
        if (binding == null) return null;
        try {
            // ViewBinding will only compile if txtTopSenders exists.
            // If it doesn't exist in your layout, this class wouldn't compile.
            // So we also provide a defensive fallback: look up by id name.
            return binding.txtTopSenders;
        } catch (Throwable ignored) {
            // fallback: attempt to find by resource id at runtime (if binding doesn't expose it)
            try {
                int id = getResources().getIdentifier("txtTopSenders", "id", requireContext().getPackageName());
                if (id != 0 && binding.getRoot() != null) {
                    View v = binding.getRoot().findViewById(id);
                    if (v instanceof TextView) return (TextView) v;
                }
            } catch (Throwable ignored2) {
            }
            return null;
        }
    }

    private String buildTopSendersText(Map<String, Integer> senderCounts, int limit) {
        if (senderCounts == null || senderCounts.isEmpty()) return "No data yet";

        // simple selection of top N (small dataset, lightweight)
        List<Map.Entry<String, Integer>> list = new ArrayList<>(senderCounts.entrySet());
        list.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));

        StringBuilder sb = new StringBuilder();
        int rank = 1;

        for (Map.Entry<String, Integer> e : list) {
            if (rank > limit) break;

            String sender = e.getKey();
            int total = e.getValue();

            // Add Zambia network label if phone number
            if (ZambiaNetworkDetector.looksLikePhoneNumber(sender)) {
                String net = ZambiaNetworkDetector.detect(sender);
                if (!"Unknown".equals(net)) sender = sender + " • " + net;
            }

            sb.append(rank).append(". ")
                    .append(sender)
                    .append(" — ")
                    .append(total)
                    .append("\n");

            rank++;
        }

        return sb.toString().trim();
    }

    private boolean isSpamVerdict(String verdict) {
        if (verdict == null) return false;
        String v = verdict.trim().toUpperCase();
        return "SPAM".equals(v);
    }

    private String safeUpper(String s) {
        if (s == null) return "";
        return s.trim().toUpperCase();
    }
}