import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Scanner;

public class TCPClient {
    public static final int SERVER_PORT = 1234;
    public static final int LOCAL_PORT = 1237;
    public static final String LOCALHOST = "localhost";  //"172.28.0.4";
    public static final String SERVER_HOST = "localhost"; //"172.28.0.5";
    public static final String QUIT = "quit";
    public static final int BUF_SIZE = 1024;

    public static void main(String[] argv) throws Exception {
        //TIRMMRT certificate for server side authentication
        System.setProperty("javax.net.ssl.trustStore", "./src/keystore/cacerts");
        System.setProperty("javax.net.ssl.trustStoreType", "JKS");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        Scanner inFromUser = new Scanner(System.in);
        Socket socket = argv.length == 0 ? new Socket(SERVER_HOST, SERVER_PORT, InetAddress.getByName(LOCALHOST), LOCAL_PORT) : getSecureSocket();
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();
        while (true) {
            String input = inFromUser.nextLine();
            if (input.equalsIgnoreCase("quit")) {
                socket.close();
                out.close();
                in.close();
                inFromUser.close();
                return;
            }
            out.write(input.getBytes());
            int n;
            byte[] buffer = new byte[BUF_SIZE];
            while ((n = in.read(buffer, 0, buffer.length)) >= 0) {
                System.out.write(buffer, 0, n);
                if (n < BUF_SIZE) break;
            }
        }
    }

    private static Socket getSecureSocket() throws IOException {
        SSLSocketFactory factory =
                (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket =
                (SSLSocket) factory.createSocket(SERVER_HOST, SERVER_PORT, InetAddress.getByName(LOCALHOST), LOCAL_PORT);
        socket.startHandshake();
        return socket;
    }
}

