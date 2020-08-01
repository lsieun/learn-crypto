package lsieun.crypto.sym.des.d_test;

import lsieun.crypto.sym.OperationType;
import lsieun.crypto.sym.des.DESUtils;
import lsieun.utils.ByteUtils;

import java.util.Arrays;

// 两个不同的秘钥，对同样的数据，加密出来的结果是一样的。
// 初始Key值为64位，但DES算法规定，其中第8、16、……64位是奇偶校验位，不参与DES运算。故Key实际可用位数便只有56位
// 参考：http://www.ltang.me/2015/11/06/java-des-secret-key/
public class Problems_With_56bit_Key {
    public static void main(String[] args) {
        byte[] msg_64_bit_bytes = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
        // 注意：两个密码的最后一位不同
        byte[] key_64_bit_bytes1 = {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
        byte[] key_64_bit_bytes2 = {'p', 'a', 's', 's', 'w', 'o', 'r', 'e'};

        // 使用不同的密钥进行加密
        byte[] encrypt_bytes1 = DESUtils.des_block_operate(msg_64_bit_bytes, key_64_bit_bytes1, OperationType.ENCRYPT);
        byte[] encrypt_bytes2 = DESUtils.des_block_operate(msg_64_bit_bytes, key_64_bit_bytes2, OperationType.ENCRYPT);

        // 判断是否相等
        System.out.println(Arrays.equals(encrypt_bytes1, encrypt_bytes2));

        System.out.println(ByteUtils.toBinary(encrypt_bytes1));
        System.out.println(ByteUtils.toBinary(encrypt_bytes2));
    }
}
