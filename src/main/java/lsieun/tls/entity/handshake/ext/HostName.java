package lsieun.tls.entity.handshake.ext;

public class HostName {
    public final int length;
    public final String name;

    public HostName(int length, String name) {
        this.length = length;
        this.name = name;
    }
}
