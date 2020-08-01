package lsieun.cert.asn1;

import lsieun.utils.DateUtils;

import java.math.BigInteger;
import java.util.Date;

public class ASN1Converter {
    public static BigInteger toBigInteger(ASN1Struct struct) {
        if (struct.tag != 2) {
            throw new RuntimeException("tag is not 2, but is " + struct.tag);
        }
        return new BigInteger(1, struct.data);
    }

    public static Date toDate(ASN1Struct struct) {
        String year = null;
        String month = null;
        String day = null;
        String hour = null;
        String minute = null;
        String second = null;

        int tag = struct.tag;
        byte[] data = struct.data;
        if (tag == 23) {
            year = String.format("%c%c", data[0], data[1]);
            int val = Integer.parseInt(year);
            if (val < 50) {
                year = "20" + year;
            }
            else {
                year = "19" + year;
            }
            month = String.format("%c%c", data[2], data[3]);
            day = String.format("%c%c", data[4], data[5]);
            hour = String.format("%c%c", data[6], data[7]);
            minute = String.format("%c%c", data[8], data[9]);
            second = String.format("%c%c", data[10], data[11]);
        }
        else if (tag == 24) {
            year = String.format("%c%c%c%c", data[0], data[1], data[2], data[3]);
            month = String.format("%c%c", data[4], data[5]);
            day = String.format("%c%c", data[6], data[7]);
            hour = String.format("%c%c", data[8], data[9]);
            minute = String.format("%c%c", data[10], data[11]);
            second = String.format("%c%c", data[12], data[13]);
        }
        else {
            throw new RuntimeException("tag is not support: " + tag);
        }

        String line = String.format("%s-%s-%s %s:%s:%s", year, month, day, hour, minute, second);
        return DateUtils.parse(line);
    }
}
