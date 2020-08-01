package lsieun.utils;

public class Pair<X, Y> {
    public final X key;
    public final Y value;

    public Pair(X key, Y value) {
        this.key = key;
        this.value = value;
    }

    @Override
    public String toString() {
        return "Pair{" +
                "key=" + key +
                ", value=" + value +
                '}';
    }
}
