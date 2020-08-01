package lsieun.tls.entity.handshake.ext;

import lsieun.utils.ByteDashboard;

import java.util.ArrayList;
import java.util.List;

public class ServerNameList extends Extension {
    public final List<ServerName> server_name_list;

    public ServerNameList(List<ServerName> server_name_list) {
        super(ExtensionType.SERVER_NAME);

        this.server_name_list = server_name_list;
    }

    public static ServerNameList parse(byte[] data) {
        ByteDashboard bd = new ByteDashboard(data);
        int server_name_list_length = bd.nextInt(2);
        List<ServerName> server_name_list = new ArrayList<>();
        while (bd.hasNext()) {
            byte name_type_val = bd.next();
            NameType name_type = NameType.valueOf(name_type_val);
            int name_length = bd.nextInt(2);
            String name = bd.nextUTF8(name_length);
            HostName host_name = new HostName(name_length, name);
            ServerName server_name = new ServerName(name_type, host_name);
            server_name_list.add(server_name);
        }

        return new ServerNameList(server_name_list);
    }
}
