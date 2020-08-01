package lsieun.tls.entity.handshake.ext;

public class ExtendedMasterSecret extends Extension {

    public ExtendedMasterSecret() {
        super(ExtensionType.EXTENDED_MASTER_SECRET);
    }

    public static ExtendedMasterSecret parse(byte[] data) {
         if (data.length != 0) {
             throw new RuntimeException("There is something you have not deal with");
         }

        return new ExtendedMasterSecret();
    }
}
