package lsieun.tls.utils;

import lsieun.tls.cst.TLSConst;
import lsieun.utils.ByteUtils;

public class TLSSession {
    public static long next_session_id = 1L;

    public static byte[] generate_new_session_id() {
        byte[] session_id = new byte[TLSConst.MAX_SESSION_ID_LENGTH];
        byte[] bytes = ByteUtils.toBytes(next_session_id);
        next_session_id++;

        int length = bytes.length;
        for (int i = 0; i < length; i++) {
            session_id[i] = bytes[i];
        }
        return session_id;
    }
}
