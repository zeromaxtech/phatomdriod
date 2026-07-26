package com.phantomdroid.app;

import android.accessibilityservice.AccessibilityService;
import android.view.accessibility.AccessibilityEvent;
import android.util.Log;

public class MonitorService extends AccessibilityService {

    private static final String TAG = "PhantomDroidMonitor";
    private DatabaseHelper dbHelper;

    @Override
    public void onCreate() {
        super.onCreate();
        dbHelper = new DatabaseHelper(this);
        Log.d(TAG, "Service Created");
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event.getEventType() == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            String packageName = event.getPackageName() != null ? event.getPackageName().toString() : "unknown";
            Log.d(TAG, "Foreground App Changed: " + packageName);
            
            // Log to local SQLite database instead of sending to localhost network
            dbHelper.insertLog("app_launch", packageName, "App opened in foreground");
        }
    }

    @Override
    public void onInterrupt() {
        Log.e(TAG, "Service Interrupted");
    }
}
