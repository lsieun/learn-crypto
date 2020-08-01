package lsieun.tls.entity.handshake.ext;

public class ServerName {
    public final NameType name_type;
    public final HostName host_name;

    public ServerName(NameType name_type, HostName host_name) {
        this.name_type = name_type;
        this.host_name = host_name;
    }
}
