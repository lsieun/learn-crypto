package lsieun.tls.entity.handshake;

import lsieun.utils.ByteDashboard;
import lsieun.utils.ByteUtils;

import java.util.Random;

public class TLSRandom {
    public final int gmt_unix_time;
    public final byte[] random_bytes;

    public TLSRandom(int gmt_unix_time) {
        this.gmt_unix_time = gmt_unix_time;
        this.random_bytes = new byte[28];
        long timestamp = System.currentTimeMillis();
        Random rand = new Random(timestamp);
        rand.nextBytes(random_bytes);
    }

    public TLSRandom(int gmt_unix_time, byte[] random_bytes) {
        this.gmt_unix_time = gmt_unix_time;
        this.random_bytes = random_bytes;
    }

    public byte[] toBytes() {
        byte[] timestamp_bytes = new byte[4];
        timestamp_bytes[0] = (byte) ((gmt_unix_time >> 24) & 0xFF);
        timestamp_bytes[1] = (byte) ((gmt_unix_time >> 16) & 0xFF);
        timestamp_bytes[2] = (byte) ((gmt_unix_time >> 8) & 0xFF);
        timestamp_bytes[3] = (byte) ((gmt_unix_time) & 0xFF);
        return ByteUtils.concatenate(timestamp_bytes, random_bytes);
    }

    public static TLSRandom fromBytes(byte[] bytes) {
        if (bytes.length != 32) {
            throw new RuntimeException("bytes' length is not 32: " + bytes.length);
        }

        ByteDashboard bd = new ByteDashboard(bytes);
        int gmt_unix_time = ByteUtils.toInt(bd.nextN(4));
        byte[] random_bytes = bd.nextN(28);

        return new TLSRandom(gmt_unix_time, random_bytes);
    }
}
