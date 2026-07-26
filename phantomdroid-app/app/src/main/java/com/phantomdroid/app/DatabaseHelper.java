package com.phantomdroid.app;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.List;

public class DatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "phantomdroid_logs.db";
    private static final int DATABASE_VERSION = 1;

    public static final String TABLE_LOGS = "logs";
    public static final String COLUMN_ID = "_id";
    public static final String COLUMN_TIMESTAMP = "timestamp";
    public static final String COLUMN_TYPE = "type";
    public static final String COLUMN_APP = "app";
    public static final String COLUMN_DESC = "description";

    private static final String TABLE_CREATE =
            "CREATE TABLE " + TABLE_LOGS + " (" +
                    COLUMN_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    COLUMN_TIMESTAMP + " INTEGER, " +
                    COLUMN_TYPE + " TEXT, " +
                    COLUMN_APP + " TEXT, " +
                    COLUMN_DESC + " TEXT" +
                    ");";

    public DatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(TABLE_CREATE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_LOGS);
        onCreate(db);
    }

    public void insertLog(String type, String app, String desc) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COLUMN_TIMESTAMP, System.currentTimeMillis());
        values.put(COLUMN_TYPE, type);
        values.put(COLUMN_APP, app);
        values.put(COLUMN_DESC, desc);
        db.insert(TABLE_LOGS, null, values);
        db.close();
    }

    public List<String> getRecentLogs() {
        List<String> logs = new ArrayList<>();
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.query(TABLE_LOGS, null, null, null, null, null, COLUMN_TIMESTAMP + " DESC", "50");

        if (cursor.moveToFirst()) {
            do {
                String app = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_APP));
                String desc = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_DESC));
                logs.add(app + " - " + desc);
            } while (cursor.moveToNext());
        }
        cursor.close();
        db.close();
        return logs;
    }
    
    public void clearLogs() {
        SQLiteDatabase db = this.getWritableDatabase();
        db.delete(TABLE_LOGS, null, null);
        db.close();
    }
}
