import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;

public class TCPClient {
    public static final int SERVER_PORT = 1234;
    public static final int CLIENT_PORT = 1237;
    public static final String LOCALHOST = "localhost";  //"172.28.0.4";
    public static final String SERVERHOST = "localhost"; //"172.28.0.5";
    public static final String QUIT = "quit";

    public static void main(String[] argv) throws Exception {
        String clientSentence = "";
        String serverSentence;
        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        Socket clientSocket = new Socket(SERVERHOST, SERVER_PORT);
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        while (!clientSentence.equalsIgnoreCase(QUIT)) {
            clientSentence = inFromUser.readLine();
            outToServer.writeBytes(clientSentence + "\n");
            serverSentence = inFromServer.readLine();
            System.out.println("FROM SERVER "+ clientSocket.getRemoteSocketAddress()+": " + serverSentence);
        }
        clientSocket.close();
        outToServer.close();
        inFromServer.close();
        inFromUser.close();
    }
}

