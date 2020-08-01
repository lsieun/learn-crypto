package lsieun.cert.asn1;

import lsieun.utils.ByteUtils;

import java.util.LinkedList;
import java.util.List;

public class ASN1Struct {
    public final boolean constructed; // bit 6 of the identifier byte
    public final int tag_class; // bits 7-8 of the identifier byte
    public final int tag; // bits 1-5 of the identifier byte

    public final int length;
    public final byte[] header;
    public final byte[] data;
    public final List<ASN1Struct> children = new LinkedList<>();

    public ASN1Struct(int tag, boolean constructed, int tag_class, int length, byte[] header, byte[] data) {
        this.tag = tag;
        this.constructed = constructed;
        this.tag_class = tag_class;
        this.length = length;
        this.header = header;
        this.data = data;
    }

    public byte[] toByteArray() {
        return ByteUtils.concatenate(header, data);
    }
}
