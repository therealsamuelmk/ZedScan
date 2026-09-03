package com.microlasan.zedscan.data.db;

import androidx.room.Entity;
import androidx.room.PrimaryKey;

@Entity(tableName = "spam_events")
public class SpamEventEntity {

    @PrimaryKey(autoGenerate = true)
    public long id;

    public String source;
    public String sender;
    public String title;
    public String bodySnippet;

    public long receivedAtMillis;

    public int spamScore;
    public String verdict;

    // Sender intelligence (device context when received)
    public String network;
    public Integer cellId;

    public Double latitude;
    public Double longitude;
    public Float accuracy;

    public SpamEventEntity(
            String source,
            String sender,
            String title,
            String bodySnippet,
            long receivedAtMillis,
            int spamScore,
            String verdict,
            String network,
            Integer cellId,
            Double latitude,
            Double longitude,
            Float accuracy
    ) {
        this.source = source;
        this.sender = sender;
        this.title = title;
        this.bodySnippet = bodySnippet;
        this.receivedAtMillis = receivedAtMillis;
        this.spamScore = spamScore;
        this.verdict = verdict;

        this.network = network;
        this.cellId = cellId;
        this.latitude = latitude;
        this.longitude = longitude;
        this.accuracy = accuracy;
    }
}