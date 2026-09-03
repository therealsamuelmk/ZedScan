package com.microlasan.zedscan.ui.history;

import android.content.Context;
import android.content.res.ColorStateList;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.ColorInt;
import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.microlasan.zedscan.R;
import com.microlasan.zedscan.data.db.SpamEventEntity;
import com.microlasan.zedscan.databinding.ItemSpamEventBinding;
import com.microlasan.zedscan.util.ZambiaNetworkDetector;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class SpamHistoryAdapter extends RecyclerView.Adapter<SpamHistoryAdapter.VH> {

    public interface Listener {
        void onItemClicked(SpamEventEntity event);
        void onItemLongPressed(SpamEventEntity event);
    }

    private final List<SpamEventEntity> items = new ArrayList<>();
    private Listener listener;

    private final SimpleDateFormat timeFmt = new SimpleDateFormat("HH:mm", Locale.getDefault());

    public void setListener(Listener listener) {
        this.listener = listener;
    }

    public void submit(List<SpamEventEntity> list) {
        items.clear();
        if (list != null) items.addAll(list);
        notifyDataSetChanged();
    }

    public SpamEventEntity getItem(int position) {
        if (position < 0 || position >= items.size()) return null;
        return items.get(position);
    }

    @NonNull
    @Override
    public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        ItemSpamEventBinding b = ItemSpamEventBinding.inflate(
                LayoutInflater.from(parent.getContext()), parent, false);
        return new VH(b);
    }

    @Override
    public void onBindViewHolder(@NonNull VH holder, int position) {
        SpamEventEntity e = items.get(position);
        Context context = holder.itemView.getContext();

        String time = e.receivedAtMillis > 0 ? timeFmt.format(new Date(e.receivedAtMillis)) : "--:--";
        String top = safe(e.source) + " • " + safe(e.verdict) + " • " + e.spamScore + " • " + time;
        holder.b.txtTop.setText(top);

        String sender = (e.sender != null ? e.sender : "Unknown");
        if ("SMS".equalsIgnoreCase(safe(e.source)) && ZambiaNetworkDetector.looksLikePhoneNumber(sender)) {
            String net = ZambiaNetworkDetector.detect(sender);
            if (!"Unknown".equals(net)) sender = sender + " • " + net;
        }
        holder.b.txtSender.setText(sender);

        holder.b.txtSnippet.setText(e.bodySnippet != null ? e.bodySnippet : "");

        if (holder.b.txtIntel != null) {
            String intel = buildIntel(e);
            holder.b.txtIntel.setText(intel);
            holder.b.txtIntel.setVisibility(intel.isEmpty() ? View.GONE : View.VISIBLE);
        }

        applyRiskStyling(context, holder, e);

        holder.itemView.setOnClickListener(v -> {
            if (listener != null) listener.onItemClicked(e);
        });

        holder.itemView.setOnLongClickListener(v -> {
            if (listener != null) listener.onItemLongPressed(e);
            return true;
        });
    }

    private void applyRiskStyling(Context context, VH holder, SpamEventEntity e) {
        int score = e.spamScore;

        @ColorInt int accent;
        @ColorInt int surface;
        String badge;

        if (score >= 80) {
            accent = ContextCompat.getColor(context, R.color.history_risk_high);
            surface = ContextCompat.getColor(context, R.color.history_risk_high_bg);
            badge = "HIGH RISK";
        } else if (score >= 60) {
            accent = ContextCompat.getColor(context, R.color.history_risk_medium);
            surface = ContextCompat.getColor(context, R.color.history_risk_medium_bg);
            badge = "SUSPICIOUS";
        } else {
            accent = ContextCompat.getColor(context, R.color.history_risk_low);
            surface = ContextCompat.getColor(context, R.color.history_risk_low_bg);
            badge = "LOW RISK";
        }

        holder.b.txtTop.setText(badge + " • " + holder.b.txtTop.getText());
        holder.b.txtTop.setTextColor(accent);

        if (holder.b.riskStripe != null) {
            holder.b.riskStripe.setBackgroundTintList(ColorStateList.valueOf(accent));
        }

        if (holder.b.riskBadge != null) {
            holder.b.riskBadge.setText(badge);
            holder.b.riskBadge.setTextColor(accent);
            holder.b.riskBadge.setBackgroundTintList(ColorStateList.valueOf(surface));
        }
    }

    private String buildIntel(SpamEventEntity e) {
        StringBuilder sb = new StringBuilder();
        try {
            if (e.network != null && !e.network.trim().isEmpty()) {
                sb.append("Network: ").append(e.network.trim());
            }
            if (e.cellId != null && e.cellId > 0) {
                if (sb.length() > 0) sb.append("\n");
                sb.append("Tower CID: ").append(e.cellId);
            }
            if (e.latitude != null && e.longitude != null) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(String.format(Locale.getDefault(),
                        "Location: %.5f, %.5f", e.latitude, e.longitude));

                if (e.accuracy != null && e.accuracy > 0) {
                    sb.append(String.format(Locale.getDefault(), " (±%.0fm)", e.accuracy));
                }
            }
        } catch (Throwable ignored) {
        }

        return sb.toString().trim();
    }

    private String safe(String s) {
        return s == null ? "" : s;
    }

    @Override
    public int getItemCount() {
        return items.size();
    }

    static class VH extends RecyclerView.ViewHolder {
        final ItemSpamEventBinding b;

        VH(ItemSpamEventBinding b) {
            super(b.getRoot());
            this.b = b;
        }
    }
}