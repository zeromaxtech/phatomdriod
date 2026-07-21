package com.phantomdroid.app;

import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        // Simple UI created in code to avoid needing XML layouts for the prototype
        android.widget.LinearLayout layout = new android.widget.LinearLayout(this);
        layout.setOrientation(android.widget.LinearLayout.VERTICAL);
        layout.setPadding(50, 50, 50, 50);

        TextView title = new TextView(this);
        title.setText("PhantomDroid V3 Watchdog");
        title.setTextSize(24f);
        layout.addView(title);

        TextView desc = new TextView(this);
        desc.setText("\nTo monitor for ad-profiling and hidden usage over the next 24 hours, you must grant Accessibility access.\n");
        layout.addView(desc);

        Button btnAccessibility = new Button(this);
        btnAccessibility.setText("Enable Accessibility Service");
        btnAccessibility.setOnClickListener(v -> {
            Intent intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
            startActivity(intent);
            Toast.makeText(this, "Find PhantomDroid and turn it ON", Toast.LENGTH_LONG).show();
        });
        layout.addView(btnAccessibility);

        Button btnUsage = new Button(this);
        btnUsage.setText("Enable Usage Access");
        btnUsage.setOnClickListener(v -> {
            Intent intent = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
            startActivity(intent);
        });
        layout.addView(btnUsage);

        setContentView(layout);
    }
}
