package lsieun.tls.entity.handshake.ext;

import lsieun.utils.ByteDashboard;

import java.util.ArrayList;
import java.util.List;

public abstract class Extension {
    public final ExtensionType extension_type;

    public Extension(ExtensionType extension_type) {
        this.extension_type = extension_type;
    }

    public static List<Extension> parse_list(byte[] extensions_bytes) {
        ByteDashboard bd = new ByteDashboard(extensions_bytes);

        List<Extension> list = new ArrayList<>();
        while (bd.hasNext()) {
            Extension ext = parse(bd);
            list.add(ext);
        }
        return list;
    }

    public static Extension parse(ByteDashboard bd) {
        int extension_type_val = bd.nextInt(2);
        ExtensionType extension_type = ExtensionType.valueOf(extension_type_val);
        int length = bd.nextInt(2);
        byte[] data = bd.nextN(length);
        switch (extension_type) {
            case SERVER_NAME: {
                return ServerNameList.parse(data);
            }
            case SUPPORTED_GROUPS: {
                return SupportedGroups.parse(data);
            }
            case EC_POINT_FORMATS: {
                return ECPointFormats.parse(data);
            }
            case EXTENDED_MASTER_SECRET: {
                return ExtendedMasterSecret.parse(data);
            }
            case SIGNATURE_ALGORITHMS: {
                return SignatureAlgorithms.parse(data);
            }
            case RENEGOTIATION_INFO:{
                return RenegotiationInfo.parse(data);
            }
            default:
                throw new RuntimeException("Unsupported extension type: " + extension_type);
        }
    }
}
