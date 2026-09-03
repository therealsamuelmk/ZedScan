package com.microlasan.zedscan.ui;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.navigation.NavController;
import androidx.navigation.fragment.NavHostFragment;
import androidx.navigation.ui.NavigationUI;

import com.microlasan.zedscan.R;
import com.microlasan.zedscan.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;

    private static final int REQ_POST_NOTIFICATIONS = 2001;
    private static final int REQ_INTEL_PERMS = 2002;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        NavHostFragment navHostFragment =
                (NavHostFragment) getSupportFragmentManager().findFragmentById(R.id.nav_host_fragment);

        if (navHostFragment != null) {
            NavController navController = navHostFragment.getNavController();
            NavigationUI.setupWithNavController(binding.bottomNav, navController);
        }

        // 1) Optional: Notification permission (Android 13+)
        requestPostNotificationsIfNeeded();

        // 2) Required for "Sender Intelligence" MVP (tower + last known location)
        requestIntelPermissionsIfNeeded();
    }

    private void requestPostNotificationsIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                        this,
                        new String[]{Manifest.permission.POST_NOTIFICATIONS},
                        REQ_POST_NOTIFICATIONS
                );
            }
        }
    }

    /**
     * Required for:
     * - TelephonyManager.getAllCellInfo() (often gated behind Location permission)
     * - LocationManager.getLastKnownLocation(...)
     *
     * NOTE: user must ALSO enable device Location (system toggle), otherwise cell info can still be empty.
     */
    private void requestIntelPermissionsIfNeeded() {
        boolean fineGranted = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;
        boolean coarseGranted = ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION)
                == PackageManager.PERMISSION_GRANTED;

        boolean phoneGranted = ContextCompat.checkSelfPermission(this, Manifest.permission.READ_PHONE_STATE)
                == PackageManager.PERMISSION_GRANTED;

        // If we already have at least coarse location and phone state, no need to ask.
        if ((fineGranted || coarseGranted) && phoneGranted) return;

        // If user previously denied with "Don't ask again", don't keep prompting every launch.
        // We'll only request if Android thinks we should show rationale OR it’s the first time.
        boolean shouldAsk =
                ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.ACCESS_FINE_LOCATION)
                        || ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.ACCESS_COARSE_LOCATION)
                        || ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.READ_PHONE_STATE)
                        || (!fineGranted && !coarseGranted) // likely first run
                        || !phoneGranted;

        if (!shouldAsk) return;

        ActivityCompat.requestPermissions(
                this,
                new String[]{
                        Manifest.permission.ACCESS_FINE_LOCATION,
                        Manifest.permission.ACCESS_COARSE_LOCATION,
                        Manifest.permission.READ_PHONE_STATE
                },
                REQ_INTEL_PERMS
        );
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        // We don't block the app if denied; ZedScan still works for spam detection.
        // But "Sender Intelligence" (tower/location) may show "Intel unavailable".
    }
}