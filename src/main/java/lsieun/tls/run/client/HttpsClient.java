package lsieun.tls.run.client;

import lsieun.tls.cst.TLSConst;
import lsieun.tls.entity.ContentType;
import lsieun.tls.entity.TLSRecord;
import lsieun.tls.entity.alert.Alert;
import lsieun.tls.entity.alert.AlertDescription;
import lsieun.tls.param.TLSClientParameters;
import lsieun.tls.run.server.HTTPSUtils;
import lsieun.tls.utils.TLSClientUtils;
import lsieun.tls.utils.TLSConnection;
import lsieun.tls.utils.TLSUtils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

public class HttpsClient {
    public static void main(String[] args) {
//        String host = "127.0.0.1";
        String host = "146.20.41.5"; // www.tetongravity.com
//        String host = "61.255.239.134"; // www.slowlens.net
//        String host = "220.181.38.150"; // baidu.com 将Server Hello/Certificate/Server Hello Done放到一个TLS Record当中
//        String host = "204.79.197.200"; // bing.com 将Server Hello/Certificate/Server Hello Done放到一个TLS Record当中
        String path = "/index.html";
        int port = TLSConst.HTTPS_PORT;

        try (
                Socket client = new Socket();
        ) {
            SocketAddress address = new InetSocketAddress(host, port);
            client.connect(address, 10000);
            client.setSoTimeout(10000);
            TLSConnection conn = new TLSConnection(client);
            System.out.println("Connection complete; negotiating TLS parameters");

            TLSClientParameters tls_context = new TLSClientParameters();
            TLSClientUtils.tls_connect(conn, tls_context);

            System.out.println("Retrieving document: " + path);

//            System.out.println("This is My Parameters:");
//            System.out.println("=========================");
//            System.out.println(HexUtils.format(tls_context.session_id, HexFormat.FORMAT_FF_SPACE_FF));
//            System.out.println(HexUtils.format(tls_context.master_secret, HexFormat.FORMAT_FF_SPACE_FF));

            HTTPSUtils.http_get(conn, tls_context, host, path);

            OUTER_LOOP:
            while (true) {
                TLSRecord tls_record = TLSUtils.tls_recv(conn, tls_context);
                ContentType content_type = tls_record.content_type;
                byte[] content = tls_record.content;

                switch (content_type) {
                    case CONTENT_ALERT:
                        Alert alert = Alert.parse(content);
                        if (alert.description == AlertDescription.CLOSE_NOTIFY) {
                            TLSUtils.tls_shutdown(conn, tls_context);
                            break OUTER_LOOP;
                        }
                        break;
                    case CONTENT_APPLICATION_DATA:
//                        System.out.println(new String(content, StandardCharsets.UTF_8));
                        break;
                    default:
                        throw new RuntimeException("Unsupported content type: " + content_type);
                }
            }


        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
