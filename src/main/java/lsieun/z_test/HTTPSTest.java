package lsieun.z_test;

import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;

// TLSv1.2: https://www.example.org
public class HTTPSTest {
    public static void main(String[] args) throws IOException {
        URL url = new URL("https://www.baidu.com");
        URLConnection conn = url.openConnection();
        try (InputStream in = conn.getInputStream()) {
            byte[] buffer = new byte[1024];
            ByteArrayOutputStream bao = new ByteArrayOutputStream();
            for (int len = in.read(buffer); len != -1;len = in.read(buffer)) {
                bao.write(buffer, 0, len);
            }
            byte[] bytes = bao.toByteArray();
            String html = new String(bytes, StandardCharsets.UTF_8);
            System.out.println(html);
        }
    }
}
