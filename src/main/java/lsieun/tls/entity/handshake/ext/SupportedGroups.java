package lsieun.tls.entity.handshake.ext;

import lsieun.utils.ByteDashboard;

import java.util.ArrayList;
import java.util.List;

public class SupportedGroups extends Extension {

    public final List<NamedCurve> named_curve_list;

    public SupportedGroups(List<NamedCurve> named_curve_list) {
        super(ExtensionType.SUPPORTED_GROUPS);
        this.named_curve_list = named_curve_list;
    }

    public static SupportedGroups parse(byte[] data) {
        ByteDashboard bd = new ByteDashboard(data);
        int supported_group_list_length = bd.nextInt(2);

        List<NamedCurve> named_curve_list = new ArrayList<>();
        int byte_counter = 0;
        while (bd.hasNext()) {
            int named_curve_val = bd.nextInt(2);
            NamedCurve named_curve = NamedCurve.valueOf(named_curve_val);
            named_curve_list.add(named_curve);
            byte_counter += 2;
        }

        if (byte_counter != supported_group_list_length) {
            throw new RuntimeException("supported_group_list_length = " + supported_group_list_length + ", byte_counter = " + byte_counter);
        }

        return new SupportedGroups(named_curve_list);
    }

}
