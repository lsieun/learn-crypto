package lsieun.crypto.sym.rc4;

public class RC4State {
    public int i = 0;
    public int j = 0;
    public byte[] S = new byte[RC4Const.RC4_STATE_ARRAY_LEN];
}
