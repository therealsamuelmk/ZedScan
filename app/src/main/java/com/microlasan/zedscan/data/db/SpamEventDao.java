package com.microlasan.zedscan.data.db;

import androidx.lifecycle.LiveData;
import androidx.room.Dao;
import androidx.room.Insert;
import androidx.room.OnConflictStrategy;
import androidx.room.Query;

import java.util.List;

@Dao
public interface SpamEventDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    long insert(SpamEventEntity event);

    @Query("SELECT * FROM spam_events ORDER BY receivedAtMillis DESC")
    LiveData<List<SpamEventEntity>> observeAll();

    // Trim + case-insensitive verdict check
    @Query("SELECT COUNT(*) FROM spam_events WHERE UPPER(TRIM(verdict)) = 'SPAM'")
    LiveData<Integer> observeSpamCount();

    // Trim + case-insensitive source + verdict check
    @Query("SELECT COUNT(*) FROM spam_events WHERE UPPER(TRIM(source)) = 'SMS' AND UPPER(TRIM(verdict)) = 'SPAM'")
    LiveData<Integer> observeSmsSpamCount();

    @Query("SELECT COUNT(*) FROM spam_events WHERE UPPER(TRIM(source)) = 'GMAIL' AND UPPER(TRIM(verdict)) = 'SPAM'")
    LiveData<Integer> observeGmailSpamCount();

    @Query("DELETE FROM spam_events")
    void clearAll();

    // Grouping by normalized source but still returning original source label
    // We return UPPER(TRIM(source)) to keep grouping consistent.
    @Query("SELECT UPPER(TRIM(source)) as source, COUNT(*) as total " +
            "FROM spam_events " +
            "WHERE UPPER(TRIM(verdict)) = 'SPAM' " +
            "GROUP BY UPPER(TRIM(source))")
    LiveData<List<SpamSourceCount>> observeSpamBySource();

    // Top senders (trim-safe verdict)
    @Query("SELECT sender as sender, COUNT(*) as total " +
            "FROM spam_events " +
            "WHERE UPPER(TRIM(verdict)) = 'SPAM' " +
            "GROUP BY sender " +
            "ORDER BY total DESC " +
            "LIMIT :limit")
    LiveData<List<TopSenderCount>> observeTopSpamSenders(int limit);

    // Top SMS spam senders (trim-safe source + verdict)
    @Query("SELECT sender as sender, COUNT(*) as total " +
            "FROM spam_events " +
            "WHERE UPPER(TRIM(verdict)) = 'SPAM' AND UPPER(TRIM(source)) = 'SMS' " +
            "GROUP BY sender " +
            "ORDER BY total DESC " +
            "LIMIT :limit")
    LiveData<List<TopSenderCount>> observeTopSmsSpamSenders(int limit);
    // NEW: per-item delete
    @Query("DELETE FROM spam_events WHERE id = :id")
    int deleteById(long id);
}