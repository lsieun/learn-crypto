package lsieun.tls.utils;

import lsieun.tls.param.TLSParameters;
import lsieun.utils.HexFormat;
import lsieun.utils.HexUtils;

import java.util.HashMap;
import java.util.Map;

public class TLSSessionStore {
    public static Map<String, byte[]> cache = new HashMap<>();

    public static void remember_session(TLSParameters tls_context) {
        byte[] session_id = tls_context.session_id;
        byte[] master_secret = tls_context.master_secret;

        String session_id_hex = HexUtils.format(session_id, HexFormat.FORMAT_FF_FF);
        cache.put(session_id_hex, master_secret);
    }

    public static void find_stored_session(byte[] session_id, TLSParameters tls_context) {
        String session_id_hex = HexUtils.format(session_id, HexFormat.FORMAT_FF_FF);

        if (cache.containsKey(session_id_hex)) {
            byte[] master_secret = cache.get(session_id_hex);
            tls_context.session_id = session_id;
            tls_context.master_secret = master_secret;
        }
    }
}
