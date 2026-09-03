package com.microlasan.zedscan.data;

import android.content.Context;

import com.microlasan.zedscan.data.db.SpamEventEntity;
import com.microlasan.zedscan.data.db.ZedScanDb;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class SpamStore {

    private static final ExecutorService IO = Executors.newSingleThreadExecutor();

    private SpamStore() {}

    public static void insert(Context context, SpamEventEntity e) {
        IO.execute(() -> ZedScanDb.get(context).spamEventDao().insert(e));
    }

    //  NEW: delete a single row
    public static void deleteById(Context context, long id) {
        IO.execute(() -> ZedScanDb.get(context).spamEventDao().deleteById(id));
    }

    // (optional) if you ever want to expose clearAll via SpamStore:
    public static void clearAll(Context context) {
        IO.execute(() -> ZedScanDb.get(context).spamEventDao().clearAll());
    }
}