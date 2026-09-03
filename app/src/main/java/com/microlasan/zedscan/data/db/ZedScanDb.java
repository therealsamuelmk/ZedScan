package com.microlasan.zedscan.data.db;

import android.content.Context;

import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;

@Database(entities = {SpamEventEntity.class}, version = 1, exportSchema = true)
public abstract class ZedScanDb extends RoomDatabase {

    private static volatile ZedScanDb INSTANCE;

    public abstract SpamEventDao spamEventDao();

    public static ZedScanDb get(Context context) {
        if (INSTANCE == null) {
            synchronized (ZedScanDb.class) {
                if (INSTANCE == null) {
                    INSTANCE = Room.databaseBuilder(
                                    context.getApplicationContext(),
                                    ZedScanDb.class,
                                    "zedscan.db"
                            )
                            .fallbackToDestructiveMigration()
                            .build();
                }
            }
        }
        return INSTANCE;
    }
}