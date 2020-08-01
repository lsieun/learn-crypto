package lsieun.crypto.hash.hmac;

@FunctionalInterface
public interface HMAC {
    byte[] apply(byte[] key_bytes, byte[] message_bytes);
}
