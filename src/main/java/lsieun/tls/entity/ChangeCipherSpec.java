package lsieun.tls.entity;

import lsieun.tls.cst.TLSConst;
import lsieun.utils.ByteDashboard;
import lsieun.utils.ByteUtils;

import java.io.ByteArrayOutputStream;

public class ChangeCipherSpec {

    public static byte[] toBytes() {
        try {
            ByteArrayOutputStream bao = new ByteArrayOutputStream();

            bao.write(ContentType.CONTENT_CHANGE_CIPHER_SPEC.val);
            bao.write(TLSConst.TLS_VERSION_MAJOR); // major
            bao.write(TLSConst.TLS_VERSION_MINOR); // minor
            bao.write(1); // length
            bao.write(1); // value

            return bao.toByteArray();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static byte[] getContent() {
        byte[] content = new byte[1];
        content[0] = 1;
        return content;
    }

}
