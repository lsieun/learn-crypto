package lsieun.tls.entity.handshake;

import lsieun.cert.asn1.PEMUtils;
import lsieun.cert.x509.SignedCertificate;
import lsieun.cert.x509.X509Utils;
import lsieun.utils.ByteDashboard;
import lsieun.utils.ByteUtils;
import lsieun.utils.FileUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class Certificate extends Handshake {

    public List<byte[]> cert_bytes_array;
    public List<SignedCertificate> cert_list;

    public Certificate(List<byte[]> cert_bytes_array) {
        super(HandshakeType.CERTIFICATE);
        this.cert_bytes_array = cert_bytes_array;
        this.cert_list = new ArrayList<>();
        for (byte[] cert_bytes : cert_bytes_array) {
            SignedCertificate signed_cert = X509Utils.parse_x509_certificate(cert_bytes);
            this.cert_list.add(signed_cert);
        }
    }

    @Override
    public byte[] getData() throws IOException {
        ByteArrayOutputStream bao = new ByteArrayOutputStream();

        int total_length = 0;
        for (byte[] bytes : cert_bytes_array) {
            total_length += bytes.length + 3;
        }

        bao.write((total_length >> 16) & 0xFF); // total length 24-bits(!)
        bao.write((total_length >> 8) & 0xFF);
        bao.write(total_length & 0xFF);

        for (byte[] bytes : cert_bytes_array) {
            int length = bytes.length;

            bao.write((length >> 16) & 0xFF); // length 24-bits(!)
            bao.write((length >> 8) & 0xFF);
            bao.write(length & 0xFF);

            bao.write(bytes);
        }

        return bao.toByteArray();

    }

    public static Certificate fromBytes(byte[] data) {
        try {
            ByteDashboard bd = new ByteDashboard(data);

            int certificates_length = ByteUtils.toInt(bd.nextN(3));

            List<byte[]> list = new ArrayList<>();
            while (bd.hasNext()) {
                int length = bd.nextInt(3);
                byte[] cert_bytes = bd.nextN(length);
                list.add(cert_bytes);
            }

            return new Certificate(list);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static Certificate getInstance() {
        String filepath = FileUtils.getFilePath("cert/rsa/signed_certificate.pem");
        byte[] cert_bytes = PEMUtils.read(filepath);
        List<byte[]> cert_bytes_array = new ArrayList<>();
        cert_bytes_array.add(cert_bytes);
        return new Certificate(cert_bytes_array);
    }

}
