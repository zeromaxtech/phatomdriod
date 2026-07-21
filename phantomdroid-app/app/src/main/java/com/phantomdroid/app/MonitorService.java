package com.phantomdroid.app;

import android.accessibilityservice.AccessibilityService;
import android.view.accessibility.AccessibilityEvent;
import android.util.Log;

import org.json.JSONObject;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class MonitorService extends AccessibilityService {

    private static final String TAG = "PhantomDroidMonitor";
    // Change this to your Railway deployment URL when ready
    private static final String BACKEND_URL = "http://localhost:5000/api/live-events"; 
    private final OkHttpClient client = new OkHttpClient();

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event.getEventType() == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            String packageName = event.getPackageName() != null ? event.getPackageName().toString() : "unknown";
            Log.d(TAG, "Foreground App Changed: " + packageName);
            
            // In a full implementation, we'd batch these in SQLite. 
            // For the prototype, we log them.
            sendEventToBackend("app_launch", packageName, "App opened in foreground");
        }
    }

    @Override
    public void onInterrupt() {
        Log.e(TAG, "Service Interrupted");
    }

    private void sendEventToBackend(String type, String app, String desc) {
        try {
            JSONObject json = new JSONObject();
            json.put("type", type);
            json.put("app", app);
            json.put("description", desc);
            json.put("timestamp", System.currentTimeMillis());

            RequestBody body = RequestBody.create(
                json.toString(), 
                MediaType.get("application/json; charset=utf-8")
            );

            Request request = new Request.Builder()
                    .url(BACKEND_URL)
                    .post(body)
                    .build();

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    Log.e(TAG, "Failed to send event: " + e.getMessage());
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    if (response.isSuccessful()) {
                        Log.d(TAG, "Event sent successfully");
                    }
                    response.close();
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
