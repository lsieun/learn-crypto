package lsieun.cert.asn1;

import lsieun.cert.cst.ObjectIdentifier;
import lsieun.utils.ByteDashboard;
import lsieun.utils.FileUtils;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Formatter;
import java.util.LinkedList;
import java.util.List;

import static lsieun.cert.asn1.ASN1Const.*;

public class ASN1Utils {
    public static List<ASN1Struct> parse_pem(String filepath) {
        List<String> lines = FileUtils.readLines(filepath);

        StringBuilder sb = new StringBuilder();
        boolean start = false;
        for (String line : lines) {
            if (line == null || "".equals(line)) continue;
            if ("".equalsIgnoreCase(line.trim())) continue;
            if (line.contains(":")) continue;
            if (line.startsWith("-----BEGIN")) {
                start = true;
                continue;
            }
            if (line.startsWith("-----END")) {
                break;
            }
            if (start) {
                sb.append(line);
            }
        }

        String base64_str = sb.toString();
        byte[] bytes = Base64.getDecoder().decode(base64_str);
        return parse_der(bytes);
    }

    public static List<ASN1Struct> parse_der(String filepath) {
        byte[] bytes = FileUtils.readBytes(filepath);
        return parse_der(bytes);
    }

    public static List<ASN1Struct> parse_der(byte[] bytes) {
        List<ASN1Struct> list = new LinkedList<>();

        ByteDashboard bd = new ByteDashboard(bytes);
        while (bd.hasNext()) {
            byte tag_byte = bd.peek();
            boolean constructed = ((tag_byte & 0x20) == 0x20); // bit 6 of the identifier byte
            int tag_class = (tag_byte & 0xC0) >> 6; // bits 7-8 of the identifier byte
            int tag = (tag_byte & 0x1F); // bits 1-5 of the identifier byte

            int length_byte = (bd.peek(1) & 0xFF);
            int length = 0;

            int header_length = 2; // 1 byte tag + 1 byte length_byte
            if ((length_byte & 0x80) == 0x80) {
                int byte_num = length_byte & 0x7F;
                header_length += byte_num;
                for (int i = 0; i < byte_num; i++) {
                    byte b = bd.peek(2 + i);
                    length = (length << 8) | (b & 0xFF);
                }

            } else {
                length = length_byte;
            }

            byte[] header = bd.nextN(header_length);
            byte[] data = bd.nextN(length);

            ASN1Struct item = new ASN1Struct(tag, constructed, tag_class, length, header, data);
            list.add(item);

            if (constructed) {
                List<ASN1Struct> sub_list = parse_der(item.data);
                item.children.addAll(sub_list);
            }
        }

        return list;
    }

    public static byte[] get_bit_string_data(ASN1Struct struct) {
        if (struct.tag != 3) {
            throw new RuntimeException("tag is not 3, but is " + struct.tag);
        }

        int length = struct.data.length;
        byte[] bytes = new byte[length - 1];
        System.arraycopy(struct.data, 1, bytes, 0, length -1);
        return bytes;
    }

    public static void show_raw(List<ASN1Struct> list) {
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        format(fm, list, 0);
        System.out.println(sb.toString());
    }

    public static void format(Formatter fm, List<ASN1Struct> list, int depth) {
        for (ASN1Struct item : list) {
            for (int i = 0; i < depth; i++) {
                fm.format("    ");
            }

            int tag = item.tag;
            int tag_class = item.tag_class;
            boolean constructed = item.constructed;
            int length = item.length;
            byte[] header = item.header;
            byte[] data = item.data;
            List<ASN1Struct> children = item.children;

            switch (tag_class) {
                case ASN1Const.ASN1_CLASS_UNIVERSAL:
                    fm.format("%s", ASN1Const.tag_names[tag]);
                    break;
                case ASN1Const.ASN1_CLASS_APPLICATION:
                    fm.format("%s", "application");
                    break;
                case ASN1Const.ASN1_CONTEXT_SPECIFIC:
                    fm.format("%s", "context");
                    break;
                case ASN1Const.ASN1_PRIVATE:
                    fm.format("%s", "private");
                    break;
            }
            fm.format(" (%d:%d)", tag, length);

            for (byte b : header) {
                fm.format(" %02X", (b & 0xFF));
            }
            if (!constructed) {
                for (int i = 0; i < length; i++) {
                    fm.format(" %02X", (data[i] & 0xFF));
                }
            }
            fm.format("%n");

            if (constructed && children.size() > 0) {
                format(fm, children, depth + 1);
            }
        }
    }

    public static void show_human_readable(List<ASN1Struct> list) {
        StringBuilder sb = new StringBuilder();
        Formatter fm = new Formatter(sb);
        format_human_readable(fm, list, 0);
        System.out.println(sb.toString());
    }

    public static void format_human_readable(Formatter fm, List<ASN1Struct> list, int depth) {
        for (ASN1Struct item : list) {
            for (int i = 0; i < depth; i++) {
                fm.format("    ");
            }

            int tag = item.tag;
            int tag_class = item.tag_class;
            boolean constructed = item.constructed;
            int length = item.length;
            byte[] header = item.header;
            byte[] data = item.data;
            List<ASN1Struct> children = item.children;

            switch (tag_class) {
                case ASN1Const.ASN1_CLASS_UNIVERSAL:
                    fm.format("%s", ASN1Const.tag_names[tag]);
                    break;
                case ASN1Const.ASN1_CLASS_APPLICATION:
                    fm.format("%s", "application");
                    break;
                case ASN1Const.ASN1_CONTEXT_SPECIFIC:
                    fm.format("%s", "context");
                    break;
                case ASN1Const.ASN1_PRIVATE:
                    fm.format("%s", "private");
                    break;
            }
            fm.format(" (%d:%d) ", tag, length);

            if (tag_class == ASN1Const.ASN1_CLASS_UNIVERSAL) {
                switch (tag) {
                    case ASN1_BOOLEAN:
                    case ASN1_INTEGER:
                    case ASN1_BIT_STRING:
                    case ASN1_OCTET_STRING:
                    case ASN1_NULL: {
                        for (byte b : header) {
                            fm.format("%02X ", (b & 0xFF));
                        }
                        for (int i = 0; i < length; i++) {
                            fm.format("%02X ", (data[i] & 0xFF));
                        }
                    }
                    break;
                    case ASN1_OBJECT_IDENTIFIER: {
                        for (byte b : header) {
                            fm.format("%02X ", (b & 0xFF));
                        }
                        fm.format("%s ", ObjectIdentifier.valueOf(data));
                    }
                    break;
                    case ASN1_SEQUENCE:
                    case ASN1_SET: {
                        for (byte b : header) {
                            fm.format("%02X ", (b & 0xFF));
                        }
                    }
                    break;
                    case ASN1_NUMERIC_STRING:
                    case ASN1_PRINTABLE_STRING:
                    case ASN1_TELETEX_STRING:
                    case ASN1_VIDEOTEX_STRING:
                    case ASN1_IA5_STRING:
                    case ASN1_UTC_TIME:
                    case ASN1_GENERALIZED_TIME:
                    case ASN1_GRAPHIC_STRING:
                    case ASN1_VISIBLE_STRING:
                    case ASN1_GENERAL_STRING:
                    case ASN1_UNIVERSAL_STRING:
                    case ASN1_CHARACTER_STRING:
                    case ASN1_BMP_STRING:
                    case ASN1_UTF8_STRING: {
                        for (byte b : header) {
                            fm.format("%02X ", (b & 0xFF));
                        }
                        fm.format("%s", new String(data, StandardCharsets.UTF_8));
                    }
                    break;
                    default:
                        break;
                }
            } else if (tag_class == ASN1Const.ASN1_CONTEXT_SPECIFIC) {
                for (byte b : header) {
                    fm.format("%02X ", (b & 0xFF));
                }
            }

            fm.format("%n");

            if (constructed && children.size() > 0) {
                format_human_readable(fm, children, depth + 1);
            }
        }
    }
}
