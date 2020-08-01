package lsieun.crypto.hash.checksum;

public class A_Test {
    public static void main(String[] args) {
        byte[] bytes = CheckSumUtils.toByteArray("abc");
        int value = CheckSumUtils.checksum(bytes);
        System.out.println(value);
    }
}
