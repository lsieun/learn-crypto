package lsieun.utils;

import javax.management.relation.RoleUnresolved;
import java.nio.charset.StandardCharsets;

/**
 * <p>
 * ByteDashboard的本质就是将一个<code>byte[]</code>放到一个类里面，那么，这么做的目的是什么呢？
 * </p>
 * <p>
 * 是为了方便读取某一段数据。我们可以将byte[]想像成一本珍贵的“历史图书”，它里面记载了很多有用的信息，同时
 * 可以将ByteDashboard想像成一个“图书錧”，我们把这本“历史图书”放到了这个“图书錧”里。
 * </p>
 * <br/>
 * <p>
 * 从内部实现上来说，可以从以下三方面来理解：
 * </p>
 * <p>
 * （1）bytes字段，表示这本“历史图书”的内容，是个最基础的信息。
 * </p>
 * <p>
 * （2）start/stop/index三个字段。是为了记录这本“历史图书”的开始页码、结束页码和当前的阅读位置，这是辅助的信息了。
 * </p>
 * <p>
 * （3）ByteDashboard类里的方法，都是围绕这4个字段来展开的。
 * </p>
 */
public class ByteDashboard {
    // 存储“数据”的部分
    private final byte[] bytes;

    //对“数据”进行记录的三个变量
    private int start;
    private int stop;
    private int index;

    public ByteDashboard(byte[] bytes) {
        this.bytes = bytes;
        this.start = 0;
        this.stop = bytes.length;
        this.index = this.start;
    }

    // region getter & setter
    public byte[] getBytes() {
        return bytes;
    }

    public int getStart() {
        return start;
    }

    public void setStart(int start) {
        this.start = start;
    }

    public int getStop() {
        return stop;
    }

    public void setStop(int stop) {
        this.stop = stop;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public int remaining() {
        if (index >= start && index <= stop) {
            return stop - index;
        }
        throw new RuntimeException("Invalid Index");
    }
    // endregion

    public boolean hasNext() {
        if (index >= start && index < stop) return true;
        return false;
    }

    public byte next() {
        byte b = this.bytes[index++];
        return b;
    }

    public byte[] nextN(int n) {
        int remaining = stop - index;
        if (remaining < n) {
            throw new RuntimeException("Remaining: " + remaining + ", Wanted: " + n);
        }
        byte[] array = new byte[n];
        for (int i = 0; i < n; i++) {
            byte b = this.bytes[index++];
            array[i] = b;
        }
        return array;
    }

    public byte[] nextN(int offset, int n) {
        index = index + offset;
        return nextN(n);
    }

    public int nextInt(int n) {
        byte[] array = nextN(n);
        return toInt(array);
    }

    private int toInt(byte[] buff) {
        int length = buff.length;
        if (length < 1 || length > 4) {
            throw new RuntimeException("Int Length should be 1~4");
        }

        int total = 0;
        for (byte b : buff) {
            total = (total << 8) | (b & 0xFF);
        }
        return total;
    }

    public String nextUTF8(int n) {
        byte[] buffer = nextN(n);
        return new String(buffer, StandardCharsets.UTF_8);
    }

    public byte peek() {
        byte b = this.bytes[index];
        return b;
    }

    public byte peek(int offset) {
        byte b = this.bytes[index + offset];
        return b;
    }

    public int peekInt(int n) {
        byte[] array = peekN(n);
        return toInt(array);
    }

    public byte[] peekN(int n) {
        byte[] array = new byte[n];
        for (int i = 0; i < n; i++) {
            byte b = this.bytes[index + i];
            array[i] = b;
        }
        return array;
    }

    public byte[] peekN(int offset, int n) {
        byte[] bytes = new byte[n];
        for (int i = 0; i < n; i++) {
            byte b = this.bytes[index + offset + i];
            bytes[i] = b;
        }
        return bytes;
    }

    public void skip(int n) {
        index = index + n;
    }

    // region readXXX
    public byte readByte() {
        byte b = next();
        return b;
    }

    // endregion

    public void reset() {
        index = this.start;
    }

    @Override
    public String toString() {
        return "ByteDashboard {" +
                "start=" + start +
                ", stop=" + stop +
                ", index=" + index +
                '}';
    }


    public static byte[] readBytes(byte[] code_bytes, int offset, int n) {
        byte[] array = new byte[n];
        for (int i = 0; i < n; i++) {
            byte b = code_bytes[offset + i];
            array[i] = b;
        }
        return array;
    }
}