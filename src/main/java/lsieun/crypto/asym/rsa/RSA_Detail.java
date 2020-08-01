package lsieun.crypto.asym.rsa;

import java.math.BigInteger;
import java.util.Random;

// http://math.hws.edu/eck/cs327_s04/RSA.java
public class RSA_Detail {
    static int bits = 128;

    public static void main(String[] str) throws java.io.IOException {

        Random random = new Random();
        System.out.println("\n\nComputing public key (N,e) and private key (N,d):");

        // Choose two large primes p and q, let N  = pq, and let p1p1 = (p-1)(q-1).

        System.out.print("Computing p ... ");
        System.out.flush();
        BigInteger p = new BigInteger(bits, 50, random);
        System.out.println(p);
        System.out.print("Computing q ... ");
        System.out.flush();
        BigInteger q = new BigInteger(bits, 50, random);
        System.out.println(q);
        BigInteger N = p.multiply(q);
        System.out.println("N = pq is       " + N);
        BigInteger p1 = p.subtract(BigInteger.ONE);
        BigInteger q1 = q.subtract(BigInteger.ONE);;
        BigInteger p1q1 = p1.multiply(q1);
        System.out.println("(p-1)(q-1) is   " + p1q1);
        System.out.println();

        // Choose numbers e and d such that e is prime and ed = 1 mod N.

        BigInteger e = new BigInteger("" + 0x10001);
        System.out.println("Using e =       " + e);
        System.out.print("Computing d ... ");
        BigInteger d = e.modInverse(p1q1);
        System.out.println(d);

        // Now, the public key is the pair (N,d) and the private key
        // is the pair (N,e).  Do some encryptions and decryptions.
        // The user enters text that is encoded into an array of
        // integers.  (Use an array, not a single integer, since
        // the algorithm can only deals with a certain number of
        // characters at a time.)  Then this array is decoded to
        // give (if the algorithm is working) the original text.

        while (true) {
            System.out.println("\n\nEnter plaintext, press return to end: ");
            System.out.print("     ");
            StringBuffer b = new StringBuffer();
            while (true) {
                int ch = System.in.read();
                if (ch == '\n' || ch == -1)
                    break;
                b.append((char)ch);
            }
            String s = b.toString();
            if (s.trim().length() == 0)
                break;
            BigInteger[] cyphertext = encode(s,N,e);
            System.out.println();
            System.out.println("Encoded Text, computed with RSA:");
            for (int i = 0; i < cyphertext.length; i++)
                System.out.println("     " + cyphertext[i]);
            String plaintext = decode(cyphertext,N,d);
            System.out.println();
            System.out.println("Decoded Text, computed with RSA:");
            System.out.println("     " + plaintext);
        }
        System.out.println();
    }


    /**
     *  Convert a string into a BigInteger.  The string should consist of
     *  ASCII characters only.  The ASCII codes are simply concatenated to
     *  give the integer.
     */
    public static BigInteger string2int(String str) {
        byte[] b = new byte[str.length()];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte)str.charAt(i);
        return new BigInteger(1,b);
    }


    /**
     *  Convert a BigInteger into a string of ASCII characters.  Each byte
     *  in the integer is simply converted into the corresponding ASCII code.
     */
    public static String int2string(BigInteger n) {
        byte[] b = n.toByteArray();
        StringBuffer s = new StringBuffer();
        for (int i = 0; i < b.length; i++)
            s.append((char)b[i]);
        return s.toString();
    }


    /**
     *  Apply RSA encryption to a string, using the key (N,e).  The string
     *  is broken into chunks, and each chunk is converted into an integer.
     *  Then that integer, x, is encoded by computing  x^e (mod N).
     */
    public static BigInteger[] encode(String plaintext, BigInteger N, BigInteger e) {
        int charsperchunk = (N.bitLength()-1)/8;
        while (plaintext.length() % charsperchunk != 0)
            plaintext += ' ';
        int chunks = plaintext.length()/ charsperchunk;
        BigInteger[] c = new BigInteger[chunks];
        for (int i = 0; i < chunks; i++) {
            String s = plaintext.substring(charsperchunk*i,charsperchunk*(i+1));
            c[i] = string2int(s);
            c[i] = c[i].modPow(e,N);
        }
        return c;
    }


    /**
     *  Apply RSA decryption to a string, using the key (N,d).  Each integer x in
     *  the array of integers is first decoded by computing  x^d (mod N).  Then
     *  each decoded integers is converted into a string, and the strings are
     *  concatenated into a single string.
     */
    public static String decode(BigInteger[] cyphertext, BigInteger N, BigInteger d) {
        String s = "";
        for (int i = 0; i < cyphertext.length; i++)
            s += int2string(cyphertext[i].modPow(d,N));
        return s;
    }

}
