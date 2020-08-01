package lsieun.crypto.hash.updateable;

@FunctionalInterface
public interface HashContextFunction {
    DigestCtx get();
}
