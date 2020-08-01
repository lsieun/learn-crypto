package lsieun.tls.utils;

import lsieun.crypto.asym.dh.DHKey;
import lsieun.crypto.asym.rsa.RSAKey;
import lsieun.crypto.asym.rsa.RSAUtils;
import lsieun.tls.cst.TLSConst;
import lsieun.utils.BigUtils;
import lsieun.utils.ByteDashboard;

import java.math.BigInteger;

public class KeyExchangeUtils {
    public static byte[] dh_key_exchange(DHKey server_dh_key, byte[] pre_master_secret) {
        BigInteger g = server_dh_key.g;
        BigInteger p = server_dh_key.p;
        BigInteger Y = server_dh_key.Y;

        // TODO: obviously, make this random, and much longer
        BigInteger a = new BigInteger("6");
        BigInteger Yc = g.modPow(a, p);
        BigInteger Z = Y.modPow(a, p);

        byte[] Z_bytes = BigUtils.toByteArray(Z);
        System.arraycopy(Z_bytes, 0, pre_master_secret, pre_master_secret.length - Z_bytes.length, Z_bytes.length);

        byte[] Yc_bytes = BigUtils.toByteArray(Yc);
        int message_size = Yc_bytes.length + 2;

        byte[] key_exchange_message = new byte[message_size];
        key_exchange_message[0] = (byte) ((message_size >> 8) & 0xFF);
        key_exchange_message[1] = (byte) (message_size & 0xFF);
        System.arraycopy(Yc_bytes, 0, key_exchange_message, 2, Yc_bytes.length);

        return key_exchange_message;
    }

    public static byte[] rsa_key_exchange(RSAKey public_key, byte[] pre_master_secret) {
        pre_master_secret[0] = TLSConst.TLS_VERSION_MAJOR;
        pre_master_secret[1] = TLSConst.TLS_VERSION_MINOR;
        for (int i = 2; i < TLSConst.MASTER_SECRET_LENGTH; i++) {
            // TODO: SHOULD BE RANDOM!
            pre_master_secret[i] = (byte) i;
        }

        byte[] encrypted_pre_master_key = RSAUtils.rsa_encrypt(pre_master_secret, public_key);
        int encrypted_length = encrypted_pre_master_key.length;

        byte[] key_exchange_message = new byte[encrypted_length + 2];
        key_exchange_message[0] = (byte) (encrypted_length >> 8 & 0xFF);
        key_exchange_message[1] = (byte) (encrypted_length & 0xFF);
        System.arraycopy(encrypted_pre_master_key, 0, key_exchange_message, 2, encrypted_length);
        return key_exchange_message;
    }

    public static byte[] decrypt_rsa_key_exchange(byte[] data, RSAKey rsaKey) {
        ByteDashboard bd = new ByteDashboard(data);
        int length = bd.nextInt(2);
        byte[] encrypted_pre_master_key = bd.nextN(length);

        return RSAUtils.rsa_decrypt(encrypted_pre_master_key, rsaKey);
    }
}
