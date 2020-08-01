package lsieun.utils;

/**
 * The following is a simple set of static methods for converting from hex to
 * bytes and vice-versa
 *
 * @author Haravikk Mistral
 * @version 1.0
 * @date Sep 15, 2008, 3:26:42 PM
 */
public class HexCoder {
    /**
     * Quick converts bytes to hex-characters
     *
     * @param bytes the byte-array to convert
     * @return the hex-representation
     */
    public static String bytesToHex(final byte[] bytes) {
        final StringBuffer sb = new StringBuffer(bytes.length * 2);
        for (int i = 0; i < bytes.length; ++i) {
            sb.append(Character.forDigit((bytes[i] >> 4) & 0xF, 16));
            sb.append(Character.forDigit(bytes[i] & 0xF, 16));
        }
        return sb.toString();
    }

    /**
     * Quickly converts hex-characters to bytes
     *
     * @param hex_str the hex-string
     * @return the bytes represented
     */
    public static byte[] hexToBytes(final String hex_str) {
        final byte[] bytes = new byte[hex_str.length() / 2];
        for (int i = 0; i < bytes.length; ++i) {
            bytes[i] = (byte) Integer.parseInt(hex_str.substring(2 * i, (2 * i) + 2), 16);
        }
        return bytes;
    }
}
