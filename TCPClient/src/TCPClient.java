import Utils.Stats;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Scanner;

public class TCPClient {
    public static final int SERVER_PORT = 1234;
    public static final String SERVER_HOST = "127.0.0.1"; // 172.28.0.5 or 127.0.0.1;
    public static final int BUF_SIZE = 512;

    public static void main(String[] argv) throws Exception {
        //TIRMMRT certificate for server side authentication
        System.setProperty("javax.net.ssl.trustStore", "./src/keystore/servers");
        System.setProperty("javax.net.ssl.trustStoreType", "JKS");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        Scanner inFromUser = new Scanner(System.in);
        Socket socket = argv.length == 0 ? new Socket(SERVER_HOST, SERVER_PORT) : getSecureSocket();
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        String input = inFromUser.nextLine();
        out.write(("GET " + input + " HTTP/1.1").getBytes());
        Stats stats = new Stats();
        int n = 0;
        byte[] buffer = new byte[BUF_SIZE];
        while ((n = in.read(buffer, 0, buffer.length)) != -1) {
            stats.newRequest(n);
            System.out.write(buffer, 0, n);
        }
        socket.close();
        stats.printReport();

    }

    private static Socket getSecureSocket() throws IOException {
        SSLSocketFactory factory =
                (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket =
                (SSLSocket) factory.createSocket(SERVER_HOST, SERVER_PORT);
        socket.startHandshake();
        return socket;
    }
}

