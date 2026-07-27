package com.phantomdroid.app;

import android.accessibilityservice.AccessibilityService;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;

import androidx.core.app.NotificationCompat;

public class MonitorService extends AccessibilityService {

    private static final String TAG = "PhantomDroidMonitor";
    private static final String CHANNEL_ID = "phantomdroid_monitor";
    private static final int NOTIFICATION_ID = 1001;
    private static final long TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000L;

    private DatabaseHelper dbHelper;
    private Handler handler;
    private Runnable autoStopRunnable;
    private Runnable notificationUpdateRunnable;
    private NotificationManager notificationManager;
    private boolean isMonitoring = false;

    @Override
    public void onCreate() {
        super.onCreate();
        dbHelper = new DatabaseHelper(this);
        handler = new Handler(Looper.getMainLooper());
        notificationManager = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);

        createNotificationChannel();
        startForegroundMonitor();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "PhantomDroid Monitor",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Shows when PhantomDroid is actively monitoring your device");
            channel.setShowBadge(false);
            notificationManager.createNotificationChannel(channel);
        }
    }

    private void startForegroundMonitor() {
        // Start the session in database
        dbHelper.startSession();
        isMonitoring = true;

        // Show persistent notification
        Notification notification = buildNotification("Monitoring started...", 0);
        startForeground(NOTIFICATION_ID, notification);

        // Schedule auto-stop after 24 hours
        autoStopRunnable = () -> {
            Log.d(TAG, "24 hours reached. Auto-stopping monitor.");
            stopMonitoring();
        };
        handler.postDelayed(autoStopRunnable, TWENTY_FOUR_HOURS_MS);

        // Update notification every 30 seconds with runtime
        notificationUpdateRunnable = new Runnable() {
            @Override
            public void run() {
                if (!isMonitoring) return;
                long startTime = dbHelper.getSessionStartTime();
                long elapsed = System.currentTimeMillis() - startTime;
                int totalEvents = dbHelper.getTotalLogCount();

                String timeStr = formatElapsed(elapsed);
                String remaining = formatElapsed(TWENTY_FOUR_HOURS_MS - elapsed);

                String text = "Running: " + timeStr + " | Events: " + totalEvents + " | Remaining: " + remaining;
                Notification n = buildNotification(text, totalEvents);
                notificationManager.notify(NOTIFICATION_ID, n);

                handler.postDelayed(this, 30000); // Update every 30s
            }
        };
        handler.postDelayed(notificationUpdateRunnable, 5000);

        Log.d(TAG, "24-hour foreground monitor started");
    }

    private void stopMonitoring() {
        isMonitoring = false;
        dbHelper.stopSession();

        // Generate report
        ReportGenerator reportGen = new ReportGenerator(this, dbHelper);
        String reportPath = reportGen.generateReport();
        if (reportPath != null) {
            Log.d(TAG, "Report saved to: " + reportPath);
            dbHelper.insertLog("report", "PhantomDroid", "24hr report saved: " + reportPath);
        }

        // Cancel scheduled tasks
        handler.removeCallbacks(autoStopRunnable);
        handler.removeCallbacks(notificationUpdateRunnable);

        // Update notification
        Notification n = buildNotification("Monitoring complete. Report saved.", dbHelper.getTotalLogCount());
        notificationManager.notify(NOTIFICATION_ID, n);

        stopForeground(false); // Keep the "complete" notification visible
    }

    private Notification buildNotification(String text, int eventCount) {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("PhantomDroid Privacy Monitor")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_menu_search)
                .setOngoing(true)
                .setCategory(NotificationCompat.CATEGORY_SERVICE)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .build();
    }

    private String formatElapsed(long ms) {
        if (ms < 0) ms = 0;
        long totalSec = ms / 1000;
        long hours = totalSec / 3600;
        long minutes = (totalSec % 3600) / 60;
        long seconds = totalSec % 60;
        return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (!isMonitoring) return;

        if (event.getEventType() == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            String packageName = event.getPackageName() != null ? event.getPackageName().toString() : "unknown";
            Log.d(TAG, "Foreground App: " + packageName);
            dbHelper.insertLog("app_launch", packageName, "App opened in foreground");
        }
    }

    @Override
    public void onInterrupt() {
        Log.e(TAG, "Service Interrupted");
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (isMonitoring) {
            stopMonitoring();
        }
        handler.removeCallbacksAndMessages(null);
    }
}
