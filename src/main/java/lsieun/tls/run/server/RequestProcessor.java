package lsieun.tls.run.server;

import lsieun.tls.param.TLSServerParameters;
import lsieun.tls.utils.TLSConnection;
import lsieun.tls.utils.TLSServerUtils;
import lsieun.tls.utils.TLSUtils;
import lsieun.tls.param.TLSParameters;

import java.io.IOException;

public class RequestProcessor extends Thread {

    public final TLSConnection conn;

    public RequestProcessor(TLSConnection conn) {
        this.conn = conn;
    }

    @Override
    public void run() {
        try {
            TLSServerParameters tls_context = new TLSServerParameters();
            TLSServerUtils.tls_accept(conn, tls_context);

            TLSUtils.tls_shutdown(conn, tls_context);
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
        finally {
            try {
                conn.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
