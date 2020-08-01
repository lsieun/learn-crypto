package lsieun.z_test;

import lsieun.utils.SSLLog;

public class LogTest {
    public static void main(String[] args) {
        String filename = "log/tlsv1.2_dhe_rsa_with_aes_256_cbc_sha.txt";
        SSLLog log = new SSLLog(filename);
        log.run();
    }
}
