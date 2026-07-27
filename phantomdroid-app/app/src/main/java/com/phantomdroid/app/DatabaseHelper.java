package com.phantomdroid.app;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class DatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "phantomdroid_logs.db";
    private static final int DATABASE_VERSION = 2;

    public static final String TABLE_LOGS = "logs";
    public static final String TABLE_SESSION = "session";

    private static final String CREATE_LOGS =
            "CREATE TABLE " + TABLE_LOGS + " (" +
                    "_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "timestamp INTEGER, " +
                    "type TEXT, " +
                    "app TEXT, " +
                    "description TEXT" +
                    ");";

    private static final String CREATE_SESSION =
            "CREATE TABLE " + TABLE_SESSION + " (" +
                    "_id INTEGER PRIMARY KEY, " +
                    "start_time INTEGER, " +
                    "end_time INTEGER, " +
                    "status TEXT DEFAULT 'stopped'" +
                    ");";

    public DatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(CREATE_LOGS);
        db.execSQL(CREATE_SESSION);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_LOGS);
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_SESSION);
        onCreate(db);
    }

    // ── Session Management ──────────────────────────────────────────

    public void startSession() {
        SQLiteDatabase db = this.getWritableDatabase();
        db.delete(TABLE_SESSION, null, null); // Only one session at a time
        ContentValues v = new ContentValues();
        v.put("_id", 1);
        v.put("start_time", System.currentTimeMillis());
        v.put("status", "running");
        db.insert(TABLE_SESSION, null, v);
        db.close();
    }

    public void stopSession() {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues v = new ContentValues();
        v.put("end_time", System.currentTimeMillis());
        v.put("status", "stopped");
        db.update(TABLE_SESSION, v, "_id=1", null);
        db.close();
    }

    public long getSessionStartTime() {
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor c = db.rawQuery("SELECT start_time FROM " + TABLE_SESSION + " WHERE _id=1", null);
        long t = 0;
        if (c.moveToFirst()) t = c.getLong(0);
        c.close();
        db.close();
        return t;
    }

    public String getSessionStatus() {
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor c = db.rawQuery("SELECT status FROM " + TABLE_SESSION + " WHERE _id=1", null);
        String s = "stopped";
        if (c.moveToFirst()) s = c.getString(0);
        c.close();
        db.close();
        return s;
    }

    // ── Logging ──────────────────────────────────────────────────────

    public void insertLog(String type, String app, String desc) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put("timestamp", System.currentTimeMillis());
        values.put("type", type);
        values.put("app", app);
        values.put("description", desc);
        db.insert(TABLE_LOGS, null, values);
        db.close();
    }

    public int getTotalLogCount() {
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor c = db.rawQuery("SELECT COUNT(*) FROM " + TABLE_LOGS, null);
        int count = 0;
        if (c.moveToFirst()) count = c.getInt(0);
        c.close();
        db.close();
        return count;
    }

    public int getUniqueAppCount() {
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor c = db.rawQuery("SELECT COUNT(DISTINCT app) FROM " + TABLE_LOGS, null);
        int count = 0;
        if (c.moveToFirst()) count = c.getInt(0);
        c.close();
        db.close();
        return count;
    }

    /** Returns the 50 most recent logs as formatted strings */
    public List<String[]> getRecentLogs(int limit) {
        List<String[]> logs = new ArrayList<>();
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.query(TABLE_LOGS, null, null, null, null, null, "timestamp DESC", String.valueOf(limit));
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());

        if (cursor.moveToFirst()) {
            do {
                long ts = cursor.getLong(cursor.getColumnIndexOrThrow("timestamp"));
                String app = cursor.getString(cursor.getColumnIndexOrThrow("app"));
                String desc = cursor.getString(cursor.getColumnIndexOrThrow("description"));
                String time = sdf.format(new Date(ts));
                logs.add(new String[]{time, app, desc});
            } while (cursor.moveToNext());
        }
        cursor.close();
        db.close();
        return logs;
    }

    /** Returns app usage counts sorted descending — for the report */
    public Map<String, Integer> getAppUsageCounts() {
        Map<String, Integer> counts = new HashMap<>();
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor c = db.rawQuery("SELECT app, COUNT(*) as cnt FROM " + TABLE_LOGS + " GROUP BY app ORDER BY cnt DESC", null);
        if (c.moveToFirst()) {
            do {
                counts.put(c.getString(0), c.getInt(1));
            } while (c.moveToNext());
        }
        c.close();
        db.close();
        return counts;
    }

    /** Returns all logs for report generation */
    public List<String[]> getAllLogs() {
        return getRecentLogs(10000); // Get everything
    }

    public void clearLogs() {
        SQLiteDatabase db = this.getWritableDatabase();
        db.delete(TABLE_LOGS, null, null);
        db.delete(TABLE_SESSION, null, null);
        db.close();
    }
}
