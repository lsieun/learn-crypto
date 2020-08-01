package lsieun.tls.entity.handshake.ext;

import java.util.Arrays;

public enum ExtensionType {
    SERVER_NAME(0),                             /* RFC 3546 */
    MAX_FRAGMENT_LENGTH(1),                     /* RFC 3546 */
    CLIENT_CERTIFICATE_URL(2),                  /* RFC 3546 */
    TRUSTED_CA_KEYS(3),                         /* RFC 3546 */
    TRUNCATED_HMAC(4),                          /* RFC 3546 */
    STATUS_REQUEST(5),                          /* RFC 3546 */
    SUPPORTED_GROUPS(10),                       /* RFC 8422 */
    EC_POINT_FORMATS(11),                       /* RFC 8422 */
    SIGNATURE_ALGORITHMS(13),                   /* RFC 8446 */
    USE_SRTP(14),                               /* RFC 5764 */
    HEARTBEAT(15),                              /* RFC 6520 */
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION(16), /* RFC 7301 */
    SIGNED_CERTIFICATE_TIMESTAMP(18),           /* RFC 6962 */
    CLIENT_CERTIFICATE_TYPE(19),                /* RFC 7250 */
    SERVER_CERTIFICATE_TYPE(20),                /* RFC 7250 */
    PADDING(21),                                /* RFC 7685 */
    EXTENDED_MASTER_SECRET(23),                 /* RFC 7627 */
    PRE_SHARED_KEY(41),                         /* RFC 8446 */
    EARLY_DATA(42),                             /* RFC 8446 */
    SUPPORTED_VERSIONS(43),                     /* RFC 8446 */
    COOKIE(44),                                 /* RFC 8446 */
    PSK_KEY_EXCHANGE_MODES(45),                 /* RFC 8446 */
    CERTIFICATE_AUTHORITIES(47),                /* RFC 8446 */
    OID_FILTERS(48),                            /* RFC 8446 */
    POST_HANDSHAKE_AUTH(49),                    /* RFC 8446 */
    SIGNATURE_ALGORITHMS_CERT(50),              /* RFC 8446 */
    KEY_SHARE(51),                              /* RFC 8446 */
    RENEGOTIATION_INFO(0xFF01),                 /* RFC 5746 */
    ;
    public final int val;

    ExtensionType(int val) {
        this.val = val;
    }

    public static ExtensionType valueOf(int val) {
        return Arrays.stream(values())
                .filter(item -> item.val == val)
                .findFirst()
                .get();
    }
}
