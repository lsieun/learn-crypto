package lsieun.tls.run.server;

import lsieun.tls.cst.TLSConst;
import lsieun.tls.entity.ContentType;
import lsieun.tls.entity.TLSRecord;
import lsieun.tls.entity.alert.Alert;
import lsieun.tls.entity.alert.AlertDescription;
import lsieun.tls.param.TLSServerParameters;
import lsieun.tls.utils.TLSConnection;
import lsieun.tls.utils.TLSServerUtils;
import lsieun.tls.utils.TLSUtils;
import lsieun.utils.ByteUtils;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class TLSWebServer {
    public static void main(String[] args) {
        int port = TLSConst.HTTPS_PORT;
        try (ServerSocket server = new ServerSocket(port)) {
            while (true) {
                Socket socket = server.accept();
                process_https_request(socket);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void process_https_request(Socket socket) {
        try {
            TLSConnection conn = new TLSConnection(socket);
            TLSServerParameters tls_context = new TLSServerParameters();
            TLSServerUtils.tls_accept(conn, tls_context);

            OUTER_LOOP:
            while (true) {
                TLSRecord tls_record = TLSUtils.tls_recv(conn, tls_context);
                ContentType content_type = tls_record.content_type;
                byte[] content = tls_record.content;

                switch (content_type) {
                    case CONTENT_ALERT:
                        Alert alert = Alert.parse(content);
                        if (alert.description == AlertDescription.CLOSE_NOTIFY) {
                            System.out.println("Client send close_notify");
                            break OUTER_LOOP;
                        }
                        break;
                    case CONTENT_APPLICATION_DATA:
                        byte[] application_data = getResponse();
                        TLSUtils.tls_send(conn, tls_context, application_data);
                        TLSUtils.tls_shutdown(conn, tls_context);
                        break;
                    default:
                        throw new RuntimeException("Unsupported content type: " + content_type);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static byte[] getResponse() {
        byte[] payload = getHTML();

        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 200 OK\r\n");
        sb.append("Server: GoodBoy\r\n");
        sb.append("Content-Type: text/html\r\n");
        sb.append("Content-Length: " + payload.length + "\r\n");
        sb.append("Connection: close\r\n\r\n");

        byte[] header = sb.toString().getBytes(StandardCharsets.UTF_8);
        return ByteUtils.concatenate(header, payload);
    }

    public static byte[] getHTML() {
        StringBuilder sb = new StringBuilder();
        sb.append("<html>");
        sb.append("<head>");
        sb.append("<title>index.html</title>");
        sb.append("</head>");
        sb.append("<body>");
        sb.append("<h1>Hello World</h1>");
        sb.append("</body>");
        sb.append("</html>");
        String html = sb.toString();
        return html.getBytes(StandardCharsets.UTF_8);
    }

    /*

Accept-Ranges: bytes
Cache-Control: no-cache


Date: Mon, 13 Jul 2020 04:40:05 GMT
P3p: CP=" OTI DSP COR IVA OUR IND COM "
P3p: CP=" OTI DSP COR IVA OUR IND COM "
Pragma: no-cache

Set-Cookie: BD_NOT_HTTPS=1; path=/; Max-Age=300
Set-Cookie: BIDUPSID=F322E623D873CCCFC55FB910AE972A33; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com
Set-Cookie: PSTM=1594615205; expires=Thu, 31-Dec-37 23:55:55 GMT; max-age=2147483647; path=/; domain=.baidu.com
Set-Cookie: BAIDUID=F322E623D873CCCF9656D63DD71C37E9:FG=1; max-age=31536000; expires=Tue, 13-Jul-21 04:40:05 GMT; domain=.baidu.com; path=/; version=1; comment=bd
Strict-Transport-Security: max-age=0
Traceid: 1594615205283822567414193230285928058921
X-Ua-Compatible: IE=Edge,chrome=1


<html>
<head>
	<script>
		location.replace(location.href.replace("https://","http://"));
	</script>
</head>
<body>
	<noscript><meta http-equiv="refresh" content="0;url=http://www.baidu.com/"></noscript>
</body>
</html>
     */
}
