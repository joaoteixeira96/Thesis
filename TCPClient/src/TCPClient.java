import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Scanner;

public class TCPClient {
    public static final int SERVER_PORT = 1234;
    public static final int LOCAL_PORT = 1237;
    public static final String LOCALHOST = "localhost";  //"172.28.0.4";
    public static final String SERVER_HOST = "localhost"; //"172.28.0.5";
    public static final String QUIT = "quit";

    public static void main(String[] argv) throws Exception {
        //TIRMMRT certificate for server side authentication
        System.setProperty("javax.net.ssl.trustStore", "./src/keystore/cacerts");
        System.setProperty("javax.net.ssl.trustStoreType", "JKS");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        String path = "";
        Scanner inFromUser = new Scanner(System.in);
        Socket clientSocket = argv.length == 0 ? new Socket(SERVER_HOST, SERVER_PORT, InetAddress.getByName(LOCALHOST), LOCAL_PORT) : getSecureSocket();
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        while (true) {
            String input = inFromUser.nextLine();
            if (input.equalsIgnoreCase("quit")) {
                clientSocket.close();
                outToServer.close();
                inFromServer.close();
                inFromUser.close();
                return;
            }
            path = "GET " + input + " HTTP/1.1";
            outToServer.writeBytes(path + "\n");
            String inputLine;
            while ((inputLine = inFromServer.readLine()).length() > 0) System.out.println(inputLine);
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

