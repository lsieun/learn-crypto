package lsieun.crypto.sym;

@FunctionalInterface
public interface BlockOperation {
    byte[] block_operate(byte[] input, byte[] key);
}
