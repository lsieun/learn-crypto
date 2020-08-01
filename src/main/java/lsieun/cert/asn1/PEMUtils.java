package lsieun.cert.asn1;

import lsieun.utils.FileUtils;

import java.util.Base64;
import java.util.List;

public class PEMUtils {
    public static byte[] read(final String filepath) {
        List<String> lines = FileUtils.readLines(filepath);

        StringBuilder sb = new StringBuilder();
        for (String line : lines) {
            if (line == null || "".equals(line)) continue;
            if (line.startsWith("-----BEGIN")) continue;
            if (line.startsWith("-----END")) continue;
            if (line.contains(":")) continue;
            if ("".equalsIgnoreCase(line.trim())) continue;
            sb.append(line);
        }

        String base64_str = sb.toString();
        byte[] decode_bytes = Base64.getDecoder().decode(base64_str);
        return decode_bytes;
    }
}
