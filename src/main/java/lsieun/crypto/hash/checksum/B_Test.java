package lsieun.crypto.hash.checksum;

import lsieun.crypto.asym.rsa.RSAConst;

import java.math.BigInteger;
import java.util.Formatter;

public class B_Test {
    public static void main(String[] args) {
        String msg1 = "Please transfer $100 to account 123";
        String msg2 = "Please transfer $1000000 to account 3789";
        String msg3 = "Transfer $1000000 to account 3789 now!";
        String[] array = {msg1, msg2, msg3};

        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        for (String msg : array) {
            byte[] bytes = CheckSumUtils.toByteArray(msg);
            int checksum = CheckSumUtils.checksum(bytes);

            BigInteger m = BigInteger.valueOf(checksum);
            BigInteger c = m.modPow(RSAConst.MINI_D, RSAConst.MINI_N);
            BigInteger decoded_c = c.modPow(RSAConst.MINI_E, RSAConst.MINI_N);

            fm.format("message: %s%n", msg);
            fm.format("checksum: %s%n", checksum);
            fm.format("RSA Sign: %s%n", c);
            fm.format("RSA Verify: %s%n%n", decoded_c);
        }

        System.out.println(sb.toString());
    }
}
