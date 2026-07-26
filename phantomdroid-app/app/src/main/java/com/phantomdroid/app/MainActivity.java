package com.phantomdroid.app;

import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.util.List;

public class MainActivity extends AppCompatActivity {

    private DatabaseHelper dbHelper;
    private android.widget.LinearLayout logsContainer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        dbHelper = new DatabaseHelper(this);

        android.widget.LinearLayout layout = new android.widget.LinearLayout(this);
        layout.setOrientation(android.widget.LinearLayout.VERTICAL);
        layout.setPadding(50, 50, 50, 50);

        TextView title = new TextView(this);
        title.setText("PhantomDroid 24Hr Dashboard");
        title.setTextSize(22f);
        title.setPadding(0, 0, 0, 30);
        layout.addView(title);

        // Buttons horizontally
        android.widget.LinearLayout buttonLayout = new android.widget.LinearLayout(this);
        buttonLayout.setOrientation(android.widget.LinearLayout.HORIZONTAL);

        Button btnAccessibility = new Button(this);
        btnAccessibility.setText("Enable Monitor");
        btnAccessibility.setOnClickListener(v -> {
            Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
            startActivity(intent);
        });
        buttonLayout.addView(btnAccessibility);

        Button btnRefresh = new Button(this);
        btnRefresh.setText("Refresh Logs");
        btnRefresh.setOnClickListener(v -> loadLogs());
        buttonLayout.addView(btnRefresh);
        
        Button btnClear = new Button(this);
        btnClear.setText("Clear");
        btnClear.setOnClickListener(v -> {
            dbHelper.clearLogs();
            loadLogs();
        });
        buttonLayout.addView(btnClear);

        layout.addView(buttonLayout);

        // Logs Area
        ScrollView scrollView = new ScrollView(this);
        logsContainer = new android.widget.LinearLayout(this);
        logsContainer.setOrientation(android.widget.LinearLayout.VERTICAL);
        scrollView.addView(logsContainer);

        layout.addView(scrollView);

        setContentView(layout);
        
        // Initial load
        loadLogs();
    }

    private void loadLogs() {
        logsContainer.removeAllViews();
        List<String> logs = dbHelper.getRecentLogs();
        
        if (logs.isEmpty()) {
            TextView tv = new TextView(this);
            tv.setText("No logs yet. Enable monitor and use some apps.");
            tv.setPadding(0, 20, 0, 0);
            logsContainer.addView(tv);
            return;
        }

        for (String log : logs) {
            TextView tv = new TextView(this);
            tv.setText(log);
            tv.setPadding(0, 15, 0, 15);
            logsContainer.addView(tv);
            
            // Divider
            android.view.View divider = new android.view.View(this);
            divider.setLayoutParams(new android.widget.LinearLayout.LayoutParams(
                    android.widget.LinearLayout.LayoutParams.MATCH_PARENT, 2));
            divider.setBackgroundColor(0xFFCCCCCC);
            logsContainer.addView(divider);
        }
    }
}
