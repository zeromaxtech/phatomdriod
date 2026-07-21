package com.phantomdroid.security;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Bitmap;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ProgressBar;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    private WebView webView;
    private ProgressBar loadingSpinner;

    private class WebAppInterface {
        Context mContext;

        WebAppInterface(Context c) {
            mContext = c;
        }

        @android.webkit.JavascriptInterface
        public String getSystemInfo() {
            return "{\"model\": \"" + android.os.Build.MODEL + 
                   "\", \"manufacturer\": \"" + android.os.Build.MANUFACTURER + 
                   "\", \"version\": \"" + android.os.Build.VERSION.RELEASE + 
                   "\", \"sdk\": " + android.os.Build.VERSION.SDK_INT + "}";
        }

        @android.webkit.JavascriptInterface
        public String getInstalledApps() {
            try {
                android.content.pm.PackageManager pm = getPackageManager();
                java.util.List<android.content.pm.PackageInfo> packages = pm.getInstalledPackages(android.content.pm.PackageManager.GET_PERMISSIONS);
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < packages.size(); i++) {
                    android.content.pm.PackageInfo p = packages.get(i);
                    String appName = p.applicationInfo.loadLabel(pm).toString();
                    
                    int permCount = 0;
                    StringBuilder sensitivePerms = new StringBuilder("[");
                    if (p.requestedPermissions != null) {
                        permCount = p.requestedPermissions.length;
                        boolean first = true;
                        for (String perm : p.requestedPermissions) {
                            String key = "";
                            if (perm.equals("android.permission.RECORD_AUDIO")) key = "RECORD_AUDIO";
                            else if (perm.equals("android.permission.CAMERA")) key = "CAMERA";
                            else if (perm.equals("android.permission.ACCESS_FINE_LOCATION")) key = "ACCESS_FINE_LOCATION";
                            else if (perm.equals("android.permission.ACCESS_BACKGROUND_LOCATION")) key = "ACCESS_BACKGROUND_LOCATION";
                            else if (perm.equals("android.permission.READ_SMS")) key = "READ_SMS";
                            else if (perm.equals("android.permission.READ_CONTACTS")) key = "READ_CONTACTS";
                            else if (perm.equals("android.permission.READ_CALL_LOG")) key = "READ_CALL_LOG";
                            else if (perm.equals("android.permission.READ_PHONE_STATE")) key = "READ_PHONE_STATE";

                            if (!key.isEmpty()) {
                                if (!first) sensitivePerms.append(",");
                                sensitivePerms.append("\"").append(key).append("\"");
                                first = false;
                            }
                        }
                    }
                    sensitivePerms.append("]");

                    sb.append("{")
                      .append("\"name\":\"").append(appName.replace("\"", "\\\"")).append("\",")
                      .append("\"package\":\"").append(p.packageName).append("\",")
                      .append("\"permissions\":").append(permCount).append(",")
                      .append("\"sensitivePerms\":").append(sensitivePerms.toString())
                      .append("}");
                    
                    if (i < packages.size() - 1) sb.append(",");
                }
                sb.append("]");
                return sb.toString();
            } catch (Exception e) {
                return "[]";
            }
        }

        @android.webkit.JavascriptInterface
        public void forceStopApp(String packageName) {
            try {
                android.content.Intent intent = new android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                intent.setData(android.net.Uri.parse("package:" + packageName));
                intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
                mContext.startActivity(intent);
                Toast.makeText(mContext, "Please click FORCE STOP for " + packageName, Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(mContext, "Error: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }

        @android.webkit.JavascriptInterface
        public void openPermissionSettings(String packageName) {
            try {
                android.content.Intent intent = new android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                intent.setData(android.net.Uri.parse("package:" + packageName));
                intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
                mContext.startActivity(intent);
                Toast.makeText(mContext, "Manage permissions for " + packageName, Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(mContext, "Error: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webview);
        loadingSpinner = findViewById(R.id.loading_spinner);

        WebSettings webSettings = webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setDomStorageEnabled(true);
        webSettings.setDatabaseEnabled(true);
        webSettings.setAllowFileAccess(true);
        webSettings.setAllowContentAccess(true);
        webSettings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        webSettings.setUseWideViewPort(true);
        webSettings.setLoadWithOverviewMode(true);
        webSettings.setSupportZoom(false);

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.KITKAT) {
            WebView.setWebContentsDebuggingEnabled(true);
        }

        webView.addJavascriptInterface(new WebAppInterface(this), "AndroidHost");

        webView.setWebChromeClient(new android.webkit.WebChromeClient() {
            @Override
            public boolean onJsAlert(WebView view, String url, String message, android.webkit.JsResult result) {
                Toast.makeText(MainActivity.this, message, Toast.LENGTH_LONG).show();
                result.confirm();
                return true;
            }
        });

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                super.onPageStarted(view, url, favicon);
                loadingSpinner.setVisibility(View.VISIBLE);
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                loadingSpinner.setVisibility(View.GONE);
                webView.setVisibility(View.VISIBLE);
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                super.onReceivedError(view, request, error);
                if (request.isForMainFrame()) {
                    Toast.makeText(MainActivity.this, "Error loading dashboard: " + error.getDescription(), Toast.LENGTH_LONG).show();
                    loadingSpinner.setVisibility(View.GONE);
                }
            }
        });

        // Load content
        if (isNetworkAvailable()) {
            webView.loadUrl("file:///android_asset/index.html");
        } else {
            Toast.makeText(this, "No internet connection. Please check your network.", Toast.LENGTH_LONG).show();
            // Still try to load local asset, though external resources might fail
            webView.loadUrl("file:///android_asset/index.html");
        }
    }

    private boolean isNetworkAvailable() {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    @Override
    public void onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
