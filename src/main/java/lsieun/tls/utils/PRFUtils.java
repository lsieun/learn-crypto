package lsieun.tls.utils;

import lsieun.crypto.hash.hmac.HMAC;
import lsieun.crypto.hash.hmac.HMACUtils;
import lsieun.tls.entity.ProtocolVersion;
import lsieun.utils.ByteUtils;

public class PRFUtils {
    public static byte[] P_hash(byte[] secret, byte[] seed, int out_len, HMAC func) {
        byte[] result_bytes = new byte[out_len];
        byte[] A = seed;

        int current_len = 0;
        while (current_len < out_len) {
            A = func.apply(secret, A);
            byte[] hash_bytes = func.apply(secret, ByteUtils.concatenate(A, seed));
            int hash_length = hash_bytes.length;

            int len = (current_len + hash_length > out_len) ? (out_len - current_len) : hash_length;
            System.arraycopy(hash_bytes, 0, result_bytes, current_len, len);
            current_len += len;
        }

        return result_bytes;
    }

    public static byte[] PRF(ProtocolVersion protocol_version, byte[] secret, byte[] label, byte[] seed, int out_len) {
        if (protocol_version.val <= ProtocolVersion.TLSv1_1.val) {
            return PRFv1_0(secret, label, seed, out_len);
        }
        else {
            return PRFv1_2(secret, label, seed, out_len);
        }
    }

    /**
     * 这里的一个问题是，secret的长度是奇数时候，该怎么处理？ <br/>
     * 在RFC 4346中，5. HMAC and the Pseudorandom Function对这个问题进行了说明。
     */
    public static byte[] PRFv1_0(byte[] secret, byte[] label, byte[] seed, int out_len) {
        int secret_len = secret.length;
        int half_secret_len = secret_len / 2;

        int remainder = secret_len % 2;
        if (remainder != 0) {
            half_secret_len += 1;
        }

        byte[] secret_first = new byte[half_secret_len];
        byte[] secret_second = new byte[half_secret_len];
        System.arraycopy(secret, 0, secret_first, 0, half_secret_len);
        System.arraycopy(secret, secret_len - half_secret_len, secret_second, 0, half_secret_len);

        byte[] input = ByteUtils.concatenate(label, seed);

        byte[] hmac_md5_bytes = P_hash(secret_first, input, out_len, HMACUtils::hmac_md5);
        byte[] hmac_sha1_bytes = P_hash(secret_second, input, out_len, HMACUtils::hmac_sha1);

        return ByteUtils.xor(hmac_md5_bytes, hmac_sha1_bytes, out_len);
    }

    public static byte[] PRFv1_2(byte[] secret, byte[] label, byte[] seed, int out_len) {
        byte[] input = ByteUtils.concatenate(label, seed);
        return P_hash(secret, input, out_len, HMACUtils::hmac_sha256);
    }
}
