package lsieun.tls.utils;

import java.io.*;
import java.net.Socket;

public class TLSConnection implements Closeable {
    public final Socket socket;
    public final InputStream in;
    public final OutputStream out;

    public TLSConnection(Socket socket) {
        this.socket = socket;

        try {
            this.in = new BufferedInputStream(socket.getInputStream());
            this.out = new BufferedOutputStream(socket.getOutputStream());
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public void send(byte[] data) throws IOException {
        this.out.write(data);
        this.out.flush();
    }

    public byte[] receive(int length) throws IOException {
        byte[] data = new byte[length];
        int accum_bytes = 0;
        while (accum_bytes < length) {
            int byte_read = this.in.read(data, accum_bytes, length - accum_bytes);
            if (byte_read == -1) {
                break;
            }
            accum_bytes += byte_read;
        }
        return data;
    }

    @Override
    public void close() throws IOException {
        if (socket != null) {
            socket.close();
        }
    }
}
