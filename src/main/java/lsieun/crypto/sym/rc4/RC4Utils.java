package lsieun.crypto.sym.rc4;

public class RC4Utils {
    public static byte[] rc4_operate(byte[] input, byte[] key) {
        byte[] S = new byte[256];
        int key_len = key.length;
        int i = 0;
        int j = 0;

        // KSA (key scheduling algorithm)
        for (i = 0; i < 256; i++) {
            S[i] = (byte) i;
        }

        j = 0;
        for (i = 0; i < 256; i++) {
            j = (j + (S[i] & 0xFF) + (key[i % key_len] & 0xFF)) % 256;
            byte tmp = S[i];
            S[i] = S[j];
            S[j] = tmp;
        }

        i = 0;
        j = 0;
        int input_length = input.length;
        byte[] output = new byte[input_length];
        for (int k = 0; k < input_length; k++) {
            i = (i + 1) % 256;
            j = (j + (S[i] & 0xFF)) % 256;
            byte tmp = S[i];
            S[i] = S[j];
            S[j] = tmp;

            output[k] = (byte) (S[((S[i] & 0xFF) + (S[j] & 0xFF)) % 256] ^ input[k]);

        }
        return output;
    }

    public static byte[] rc4_operate(byte[] input, byte[] key, RC4State state) {
        int i = state.i;
        int j = state.j;
        byte[] S = state.S;

        // KSA (key scheduling algorithm)
        if (S[0] == 0 && S[1] == 0) {
            for (i = 0; i < 256; i++) {
                S[i] = (byte) i;
            }

            j = 0;
            int key_len = key.length;
            for (i = 0; i < 256; i++) {
                j = (j + (S[i] & 0xFF) + (key[i % key_len] & 0xFF)) % 256;
                byte tmp = S[i];
                S[i] = S[j];
                S[j] = tmp;
            }

            i = 0;
            j = 0;
        }

        int input_length = input.length;
        byte[] output = new byte[input_length];
        for (int k = 0; k < input_length; k++) {
            i = (i + 1) % 256;
            j = (j + (S[i] & 0xFF)) % 256;
            byte tmp = S[i];
            S[i] = S[j];
            S[j] = tmp;

            output[k] = (byte) (S[((S[i] & 0xFF) + (S[j] & 0xFF)) % 256] ^ input[k]);

        }

        state.i = i;
        state.j = j;

        return output;
    }
}
