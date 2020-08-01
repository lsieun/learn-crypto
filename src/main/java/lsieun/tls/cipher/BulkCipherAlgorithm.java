package lsieun.tls.cipher;

import lsieun.crypto.sym.BlockOperation;
import lsieun.crypto.sym.aes.AESUtils;
import lsieun.crypto.sym.des.DESUtils;

public enum BulkCipherAlgorithm {
    NULL(CipherType.NULL, 0, 0, null, null),
    RC4(CipherType.STREAM, 0, 16, null, null),
    DES(CipherType.BLOCK, 8, 8, DESUtils::des_block_encrypt, DESUtils::des_block_decrypt),
    TRIPLE_DES(CipherType.BLOCK, 8, 24, DESUtils::des_block_encrypt, DESUtils::des_block_decrypt),
    AES128(CipherType.BLOCK, 16, 16, AESUtils::aes_block_encrypt, AESUtils::aes_block_decrypt),
    AES256(CipherType.BLOCK, 16, 32, AESUtils::aes_block_encrypt, AESUtils::aes_block_decrypt),
    ;

    public final CipherType cipher_type;
    public final int block_size;
    public final int key_size;
    public final BlockOperation bulk_encrypt;
    public final BlockOperation bulk_decrypt;

    BulkCipherAlgorithm(CipherType cipher_type, int block_size, int key_size, BlockOperation bulk_encrypt, BlockOperation bulk_decrypt) {
        this.cipher_type = cipher_type;
        this.block_size = block_size;
        this.key_size = key_size;
        this.bulk_encrypt = bulk_encrypt;
        this.bulk_decrypt = bulk_decrypt;
    }


}
