package lsieun.crypto.asym.rsa.e_example;

import lsieun.crypto.asym.rsa.RSAKey;
import lsieun.crypto.asym.rsa.RSAUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

public class RSATest {
    public static final BigInteger MODULUS = new BigInteger("9616540267013058477253762977293425063379243458473593816900454019721117570003248808113992652836857529658675570356835067184715201230519907361653795328462699");
    public static final BigInteger PUBLIC_EXPONENT = new BigInteger("65537");
    public static final BigInteger PRIVATE_EXPONENT = new BigInteger("4802033916387221748426181350914821072434641827090144975386182740274856853318276518446521844642275539818092186650425384826827514552122318308590929813048801");

    public static void main(String[] args) {
        RSAKey pri_key = new RSAKey(MODULUS, PRIVATE_EXPONENT);
        RSAKey pub_key = new RSAKey(MODULUS, PUBLIC_EXPONENT);

//        String msg = "hello world";
//        byte[] input = msg.getBytes(StandardCharsets.UTF_8);

        byte[] input = new byte[10000];
        long timestamp = System.currentTimeMillis();
        Random rand = new Random(timestamp);
        for (int i=0;i<10000;i++) {
            input[i] = (byte) rand.nextInt();
        }

        byte[] encrypted_bytes = RSAUtils.rsa_encrypt(input, pub_key);
        byte[] decrypted_bytes = RSAUtils.rsa_decrypt(encrypted_bytes, pri_key);
        System.out.println(Arrays.equals(input, decrypted_bytes));
    }
}
