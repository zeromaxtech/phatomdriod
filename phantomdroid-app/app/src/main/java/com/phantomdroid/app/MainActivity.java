package com.phantomdroid.app;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.util.List;

public class MainActivity extends AppCompatActivity {

    private DatabaseHelper dbHelper;
    private TextView tvStatus;
    private TextView tvTimer;
    private TextView tvEventCount;
    private TextView tvAppCount;
    private LinearLayout logsContainer;
    private Handler timerHandler;
    private Runnable timerRunnable;
    private Runnable autoRefreshRunnable;
    private static final long TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000L;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dbHelper = new DatabaseHelper(this);
        timerHandler = new Handler(Looper.getMainLooper());

        // Request storage permission for saving reports
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, 100);
        }

        buildUI();
        startTimerUpdates();
        startAutoRefresh();
    }

    private void buildUI() {
        // Root layout
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#121212"));
        root.setPadding(40, 60, 40, 40);

        // ── Title ──
        TextView title = new TextView(this);
        title.setText("PHANTOMDROID");
        title.setTextSize(20f);
        title.setTextColor(Color.parseColor("#00E676"));
        title.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        title.setLetterSpacing(0.3f);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView subtitle = new TextView(this);
        subtitle.setText("24-Hour Privacy Watchdog");
        subtitle.setTextSize(12f);
        subtitle.setTextColor(Color.parseColor("#888888"));
        subtitle.setGravity(Gravity.CENTER);
        subtitle.setPadding(0, 0, 0, 30);
        root.addView(subtitle);

        // ── Status Card ──
        LinearLayout statusCard = createCard();

        tvStatus = new TextView(this);
        tvStatus.setText("● STOPPED");
        tvStatus.setTextSize(18f);
        tvStatus.setTextColor(Color.parseColor("#FF5252"));
        tvStatus.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        tvStatus.setGravity(Gravity.CENTER);
        statusCard.addView(tvStatus);

        tvTimer = new TextView(this);
        tvTimer.setText("00:00:00 / 24:00:00");
        tvTimer.setTextSize(28f);
        tvTimer.setTextColor(Color.WHITE);
        tvTimer.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        tvTimer.setGravity(Gravity.CENTER);
        tvTimer.setPadding(0, 15, 0, 15);
        statusCard.addView(tvTimer);

        // Stats row
        LinearLayout statsRow = new LinearLayout(this);
        statsRow.setOrientation(LinearLayout.HORIZONTAL);
        statsRow.setGravity(Gravity.CENTER);

        tvEventCount = new TextView(this);
        tvEventCount.setText("Events: 0");
        tvEventCount.setTextColor(Color.parseColor("#64FFDA"));
        tvEventCount.setTypeface(Typeface.MONOSPACE);
        tvEventCount.setPadding(0, 0, 40, 0);
        statsRow.addView(tvEventCount);

        tvAppCount = new TextView(this);
        tvAppCount.setText("Apps: 0");
        tvAppCount.setTextColor(Color.parseColor("#FFD740"));
        tvAppCount.setTypeface(Typeface.MONOSPACE);
        statsRow.addView(tvAppCount);

        statusCard.addView(statsRow);
        root.addView(statusCard);

        // ── Buttons Row ──
        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);
        btnRow.setPadding(0, 20, 0, 20);
        btnRow.setGravity(Gravity.CENTER);

        Button btnEnable = createButton("ENABLE MONITOR", "#00E676");
        btnEnable.setOnClickListener(v -> {
            Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
            startActivity(intent);
            Toast.makeText(this, "Find 'PhantomDroid' and turn it ON", Toast.LENGTH_LONG).show();
        });
        btnRow.addView(btnEnable);

        Button btnReport = createButton("GENERATE REPORT", "#FFD740");
        btnReport.setOnClickListener(v -> {
            ReportGenerator gen = new ReportGenerator(this, dbHelper);
            String path = gen.generateReport();
            if (path != null) {
                Toast.makeText(this, "Report saved to:\n" + path, Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(this, "Failed to generate report", Toast.LENGTH_SHORT).show();
            }
        });
        btnRow.addView(btnReport);

        root.addView(btnRow);

        // ── Secondary Buttons Row ──
        LinearLayout btnRow2 = new LinearLayout(this);
        btnRow2.setOrientation(LinearLayout.HORIZONTAL);
        btnRow2.setPadding(0, 0, 0, 20);
        btnRow2.setGravity(Gravity.CENTER);

        Button btnRefresh = createButton("REFRESH", "#64FFDA");
        btnRefresh.setOnClickListener(v -> refreshLogs());
        btnRow2.addView(btnRefresh);

        Button btnClear = createButton("CLEAR ALL", "#FF5252");
        btnClear.setOnClickListener(v -> {
            dbHelper.clearLogs();
            refreshLogs();
            Toast.makeText(this, "All logs cleared", Toast.LENGTH_SHORT).show();
        });
        btnRow2.addView(btnClear);

        root.addView(btnRow2);

        // ── Logs Header ──
        TextView logsHeader = new TextView(this);
        logsHeader.setText("LIVE ACTIVITY LOG");
        logsHeader.setTextSize(14f);
        logsHeader.setTextColor(Color.parseColor("#00E676"));
        logsHeader.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        logsHeader.setPadding(0, 10, 0, 10);
        root.addView(logsHeader);

        // ── Logs ScrollView ──
        ScrollView scrollView = new ScrollView(this);
        scrollView.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        logsContainer = new LinearLayout(this);
        logsContainer.setOrientation(LinearLayout.VERTICAL);
        logsContainer.setBackgroundColor(Color.parseColor("#1A1A2E"));
        logsContainer.setPadding(20, 20, 20, 20);
        scrollView.addView(logsContainer);

        root.addView(scrollView);

        setContentView(root);

        // Initial refresh
        refreshLogs();
    }

    private LinearLayout createCard() {
        LinearLayout card = new LinearLayout(this);
        card.setOrientation(LinearLayout.VERTICAL);
        card.setBackgroundColor(Color.parseColor("#1E1E2E"));
        card.setPadding(30, 30, 30, 30);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 10, 0, 10);
        card.setLayoutParams(lp);
        return card;
    }

    private Button createButton(String text, String color) {
        Button btn = new Button(this);
        btn.setText(text);
        btn.setTextSize(11f);
        btn.setTextColor(Color.parseColor("#121212"));
        btn.setBackgroundColor(Color.parseColor(color));
        btn.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        btn.setPadding(20, 10, 20, 10);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f);
        lp.setMargins(5, 0, 5, 0);
        btn.setLayoutParams(lp);
        return btn;
    }

    private void refreshLogs() {
        logsContainer.removeAllViews();

        // Update stats
        int events = dbHelper.getTotalLogCount();
        int apps = dbHelper.getUniqueAppCount();
        tvEventCount.setText("Events: " + events);
        tvAppCount.setText("Apps: " + apps);

        // Update status
        String status = dbHelper.getSessionStatus();
        if ("running".equals(status)) {
            tvStatus.setText("● MONITORING ACTIVE");
            tvStatus.setTextColor(Color.parseColor("#00E676"));
        } else {
            tvStatus.setText("● STOPPED");
            tvStatus.setTextColor(Color.parseColor("#FF5252"));
        }

        // Show logs
        List<String[]> logs = dbHelper.getRecentLogs(50);

        if (logs.isEmpty()) {
            TextView tv = new TextView(this);
            tv.setText("No logs yet.\n\n1. Tap ENABLE MONITOR\n2. Find PhantomDroid in Accessibility\n3. Turn it ON\n4. Use your phone normally");
            tv.setTextColor(Color.parseColor("#666666"));
            tv.setTypeface(Typeface.MONOSPACE);
            tv.setPadding(10, 20, 10, 20);
            logsContainer.addView(tv);
            return;
        }

        for (String[] log : logs) {
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setPadding(0, 8, 0, 8);

            // Time
            TextView tvTime = new TextView(this);
            tvTime.setText(log[0]);
            tvTime.setTextColor(Color.parseColor("#888888"));
            tvTime.setTypeface(Typeface.MONOSPACE);
            tvTime.setTextSize(11f);
            tvTime.setPadding(0, 0, 15, 0);
            row.addView(tvTime);

            // App name (cleaned)
            String appName = log[1];
            if (appName.contains(".")) {
                String[] parts = appName.split("\\.");
                appName = parts[parts.length - 1];
            }
            TextView tvApp = new TextView(this);
            tvApp.setText(appName);
            tvApp.setTextColor(Color.parseColor("#64FFDA"));
            tvApp.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
            tvApp.setTextSize(12f);
            row.addView(tvApp);

            logsContainer.addView(row);

            // Divider
            View divider = new View(this);
            divider.setLayoutParams(new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, 1));
            divider.setBackgroundColor(Color.parseColor("#333333"));
            logsContainer.addView(divider);
        }
    }

    private void startTimerUpdates() {
        timerRunnable = new Runnable() {
            @Override
            public void run() {
                long startTime = dbHelper.getSessionStartTime();
                if (startTime > 0 && "running".equals(dbHelper.getSessionStatus())) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    String elapsedStr = formatTime(elapsed);
                    String remainingStr = formatTime(Math.max(0, TWENTY_FOUR_HOURS_MS - elapsed));
                    tvTimer.setText(elapsedStr + " / 24:00:00");

                    // Update event count live
                    tvEventCount.setText("Events: " + dbHelper.getTotalLogCount());
                    tvAppCount.setText("Apps: " + dbHelper.getUniqueAppCount());
                } else {
                    tvTimer.setText("00:00:00 / 24:00:00");
                }
                timerHandler.postDelayed(this, 1000); // Update every second
            }
        };
        timerHandler.postDelayed(timerRunnable, 500);
    }

    private void startAutoRefresh() {
        autoRefreshRunnable = new Runnable() {
            @Override
            public void run() {
                refreshLogs();
                timerHandler.postDelayed(this, 10000); // Auto-refresh logs every 10 seconds
            }
        };
        timerHandler.postDelayed(autoRefreshRunnable, 10000);
    }

    private String formatTime(long ms) {
        if (ms < 0) ms = 0;
        long totalSec = ms / 1000;
        long hours = totalSec / 3600;
        long minutes = (totalSec % 3600) / 60;
        long seconds = totalSec % 60;
        return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshLogs();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        timerHandler.removeCallbacksAndMessages(null);
    }
}
