package lsieun.utils;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileUtils {
    public static String getFilePath(String relativePath) {
        return FileUtils.class.getClassLoader().getResource(relativePath).getPath();
    }

    public static byte[] readBytes(String filename) {
        File file = new File(filename);
        if (!file.exists()) {
            throw new IllegalArgumentException("filename: " + filename + " does not exist!");
        }

        try (
                FileInputStream fin = new FileInputStream(file);
                BufferedInputStream bin = new BufferedInputStream(fin);
        ) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();

            byte[] buff = new byte[1024 * 256];

            for (int len = bin.read(buff); len != -1; len = bin.read(buff)) {
                out.write(buff, 0, len);
            }
            return out.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void writeBytes(String filename, byte[] bytes) {
        File file = new File(filename);
        File dir = file.getParentFile();
        if (!dir.exists()) {
            boolean flag = dir.mkdirs();
            if (!flag) {
                throw new RuntimeException("create Directory Failed: " + dir);
            }
        }

        try (
                OutputStream out = new FileOutputStream(filename);
                BufferedOutputStream buff = new BufferedOutputStream(out)
        ) {
            buff.write(bytes);
            buff.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static List<String> readLines(String filepath) {
        return readLines(filepath, "UTF8");
    }

    public static List<String> readLines(String filepath, String charsetName) {
        File file = new File(filepath);
        if (!file.exists()) {
            throw new IllegalArgumentException("filepath does not exist: " + filepath);
        }

        try (
                InputStream in = new FileInputStream(file);
                Reader reader = new InputStreamReader(in, charsetName);
                BufferedReader bufferReader = new BufferedReader(reader)
        ) {

            List<String> list = new ArrayList<>();
            String line;
            while ((line = bufferReader.readLine()) != null) {
                list.add(line);
            }
            return list;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static void writeLines(String filename, List<String> lines) {
        if (lines == null || lines.size() < 1) return;

        File file = new File(filename);
        File dirFile = file.getParentFile();
        if (!dirFile.exists()) {
            boolean flag = dirFile.mkdirs();
            if (!flag) {
                throw new RuntimeException("create Directory Failed: " + dirFile.getAbsolutePath());
            }
        }


        try (
                OutputStream out = new FileOutputStream(file);
                Writer writer = new OutputStreamWriter(out, "UTF8");
                BufferedWriter bufferedWriter = new BufferedWriter(writer);
        ) {
            for (String line : lines) {
                bufferedWriter.write(line + System.lineSeparator());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
