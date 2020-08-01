package lsieun.tls.entity.handshake.ext;

import lsieun.utils.ByteDashboard;

import java.util.ArrayList;
import java.util.List;

public class ECPointFormats extends Extension {
    public final List<ECPointFormat> ec_point_format_list;

    public ECPointFormats(List<ECPointFormat> ec_point_format_list) {
        super(ExtensionType.EC_POINT_FORMATS);
        this.ec_point_format_list = ec_point_format_list;
    }

    public static ECPointFormats parse(byte[] data) {
        ByteDashboard bd = new ByteDashboard(data);
        int ec_point_format_list_length = bd.nextInt(1);

        int byte_counter = 0;
        List<ECPointFormat> ec_point_format_list = new ArrayList<>();
        while (bd.hasNext()) {
            int ec_point_format_val = bd.nextInt(1);
            ECPointFormat ec_point_format = ECPointFormat.valueOf(ec_point_format_val);
            ec_point_format_list.add(ec_point_format);
            byte_counter += 1;
        }

        if (byte_counter != ec_point_format_list_length) {
            throw new RuntimeException("ec_point_format_list_length = " + ec_point_format_list_length + ", byte_counter = " + byte_counter);
        }

        return new ECPointFormats(ec_point_format_list);
    }

}
