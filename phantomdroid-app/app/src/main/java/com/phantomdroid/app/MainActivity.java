package com.phantomdroid.app;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "PhantomDroidMain";
    private static final String PREFS_NAME = "phantomdroid_prefs";
    private static final String KEY_CRASH_FLAG = "crash_on_launch";
    private static final int STORAGE_PERMISSION_CODE = 100;

    private DatabaseHelper dbHelper;
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        // ── RASP Self-Healing Recovery Loop ──
        setupRecoveryHandler();

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        dbHelper = new DatabaseHelper(this);

        // Check if we booted from a crash state
        checkRecoveryState();

        // Request storage permission
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, STORAGE_PERMISSION_CODE);
        }

        // Initialize WebView
        initWebView();
    }

    private void setupRecoveryHandler() {
        final Thread.UncaughtExceptionHandler defaultHandler = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, throwable) -> {
            Log.e(TAG, "Uncaught Exception detected! Triggering self-healing recovery flag.", throwable);
            
            // Set crash flag in SharedPreferences
            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            prefs.edit().putBoolean(KEY_CRASH_FLAG, true).apply();

            // Clear configuration caches to prevent loop
            try {
                dbHelper.clearLogs();
            } catch (Exception e) {
                // Ignore db errors during crash handling
            }

            // Fallback to default Android handler
            if (defaultHandler != null) {
                defaultHandler.uncaughtException(thread, throwable);
            }
        });
    }

    private void checkRecoveryState() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        boolean crashedOnLaunch = prefs.getBoolean(KEY_CRASH_FLAG, false);
        if (crashedOnLaunch) {
            Log.w(TAG, "System recovered from a launch-crash loop. Safe mode active.");
            Toast.makeText(this, "🛡️ Safe mode: Configuration reset to prevent crash loop.", Toast.LENGTH_LONG).show();
            
            // Reset the flag
            prefs.edit().putBoolean(KEY_CRASH_FLAG, false).apply();
            
            // Purge DB to remove corrupt records
            try {
                dbHelper.clearLogs();
                dbHelper.insertLog("system", "PhantomDroid", "System self-healed successfully after crash.");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void initWebView() {
        webView = findViewById(R.id.webview);
        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setAllowFileAccess(true);

        // Inject the Javascript bridge
        webView.addJavascriptInterface(new WebAppInterface(this), "AndroidBridge");

        // Load the HTML file from local assets folder
        webView.loadUrl("file:///android_asset/index.html");
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (webView != null) {
            webView.reload(); // Refresh screen state when returning to app
        }
    }

    // ── Javascript Bridge Interface ──
    public class WebAppInterface {
        Context mContext;

        WebAppInterface(Context c) {
            mContext = c;
        }

        @JavascriptInterface
        public String getRecentLogs() {
            try {
                List<String[]> rawLogs = dbHelper.getRecentLogs(50);
                JSONArray array = new JSONArray();
                for (String[] log : rawLogs) {
                    JSONObject obj = new JSONObject();
                    obj.put("time", log[0]);
                    obj.put("app", log[1]);
                    obj.put("desc", log[2]);
                    array.put(obj);
                }
                return array.toString();
            } catch (Exception e) {
                return "[]";
            }
        }

        @JavascriptInterface
        public String getStats() {
            try {
                JSONObject obj = new JSONObject();
                obj.put("status", dbHelper.getSessionStatus());
                obj.put("events", dbHelper.getTotalLogCount());
                obj.put("apps", dbHelper.getUniqueAppCount());
                obj.put("startTime", dbHelper.getSessionStartTime());
                obj.put("currentTime", System.currentTimeMillis());
                return obj.toString();
            } catch (Exception e) {
                return "{}";
            }
        }

        @JavascriptInterface
        public void enableMonitor() {
            Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
            mContext.startActivity(intent);
        }

        @JavascriptInterface
        public String generateReport() {
            ReportGenerator gen = new ReportGenerator(mContext, dbHelper);
            String path = gen.generateReport();
            if (path != null) {
                return "Report saved to: " + path;
            } else {
                return "Error generating report";
            }
        }

        @JavascriptInterface
        public void clearLogs() {
            dbHelper.clearLogs();
        }
    }
}
