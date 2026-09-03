package com.microlasan.zedscan.ui.map;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.microlasan.zedscan.databinding.FragmentMapOsmBinding;

import java.util.Locale;

public class MapFragment extends Fragment {

    private FragmentMapOsmBinding binding;

    private String sender;
    private String network;
    private int cellId;
    private double lat;
    private double lng;
    private float acc;

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        binding = FragmentMapOsmBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        Bundle args = getArguments();
        if (args != null) {
            sender = args.getString("sender", "Unknown");
            network = args.getString("network", "Unknown");
            cellId = args.getInt("cellId", -1);
            lat = args.getDouble("lat", 0);
            lng = args.getDouble("lng", 0);
            acc = args.getFloat("acc", -1f);
        }

        // Native bottom details (no web needed)
        binding.txtSender.setText(sender == null ? "Unknown" : sender);
        binding.txtNetwork.setText((network == null || network.trim().isEmpty()) ? "Unknown" : network.trim());
        binding.txtCellId.setText(cellId > 0 ? String.valueOf(cellId) : "N/A");
        binding.txtCoords.setText(String.format(Locale.getDefault(), "%.6f, %.6f", lat, lng));
        binding.txtAccuracy.setText(acc > 0 ? String.format(Locale.getDefault(), "%.0fm", acc) : "N/A");

        // Load Leaflet map from assets (OSM tiles)
        binding.webMap.getSettings().setJavaScriptEnabled(true);
        binding.webMap.getSettings().setDomStorageEnabled(true);
        binding.webMap.getSettings().setLoadWithOverviewMode(true);
        binding.webMap.getSettings().setUseWideViewPort(true);

        // Optional (helps some Android versions)
        binding.webMap.getSettings().setAllowFileAccess(true);
        binding.webMap.getSettings().setAllowContentAccess(true);

        // Load HTML
        binding.webMap.loadUrl("file:///android_asset/osm_map.html");

        // When the page finishes, call JS to set marker
        binding.webMap.setWebViewClient(new android.webkit.WebViewClient() {
            @Override
            public void onPageFinished(android.webkit.WebView view, String url) {
                super.onPageFinished(view, url);

                // Escape strings for JS
                String sSender = jsEscape(sender);
                String sNetwork = jsEscape(network);

                String js = "javascript:setEvent("
                        + lat + ","
                        + lng + ","
                        + cellId + ","
                        + (acc > 0 ? acc : -1) + ","
                        + "'" + sSender + "',"
                        + "'" + sNetwork + "'"
                        + ");";

                view.evaluateJavascript(js, null);
            }
        });
    }

    private String jsEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\n", " ")
                .replace("\r", " ");
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        if (binding != null) {
            binding.webMap.destroy();
        }
        binding = null;
    }
}