package lsieun.crypto.sym.des;

import lsieun.crypto.sym.modes.CBCUtils;
import lsieun.utils.PaddingUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DES_CBC_PKCS5Padding_Verify {
    public static void main(String[] args) {
        byte[] plain_text_bytes = "你知道吗？在.class文件中，Magic Number的值是0xcafebabe。".getBytes(StandardCharsets.UTF_8);
        byte[] key_bytes = DESSample.key;
        byte[] initialization_vector_bytes = new byte[]{0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78};

        // 加密
        byte[] encrypted_bytes1 = JDK_DES_CBC_PKCS5Padding.encrypt(plain_text_bytes, key_bytes, initialization_vector_bytes);
        byte[] encrypted_bytes2 = DES_CBC_PKCS5Padding.des_cbc_encrypt(plain_text_bytes, key_bytes, initialization_vector_bytes);

        byte[] padded_input = PaddingUtils.add_pkcs5_padding(plain_text_bytes, 8);
        byte[] encrypted_bytes3 = CBCUtils.cbc_encrypt(padded_input, key_bytes, initialization_vector_bytes, 8, DESUtils::des_block_encrypt);
        System.out.println(Arrays.equals(encrypted_bytes1, encrypted_bytes2));
        System.out.println(Arrays.equals(encrypted_bytes1, encrypted_bytes3));

        // 解密
        byte[] decrypted_bytes1 = JDK_DES_CBC_PKCS5Padding.decrypt(encrypted_bytes1, key_bytes, initialization_vector_bytes);
        byte[] decrypted_bytes2 = DES_CBC_PKCS5Padding.des_cbc_decrypt(encrypted_bytes1, key_bytes, initialization_vector_bytes);
        byte[] decrypted_bytes3 = CBCUtils.cbc_decrypt(encrypted_bytes1, key_bytes, initialization_vector_bytes, 8, DESUtils::des_block_decrypt);
        byte[] remove_pad_bytes = PaddingUtils.remove_pkcs5_padding(decrypted_bytes3);
        System.out.println(Arrays.equals(decrypted_bytes1, decrypted_bytes2));
        System.out.println(Arrays.equals(decrypted_bytes1, remove_pad_bytes));

        System.out.println(new String(decrypted_bytes1, StandardCharsets.UTF_8));
    }

}
