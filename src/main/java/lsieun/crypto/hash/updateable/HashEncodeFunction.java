package lsieun.crypto.hash.updateable;

@FunctionalInterface
public interface HashEncodeFunction {
    byte[] encode(int[] hash);
}
