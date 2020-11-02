import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Scanner;

public class TCPClient {
    public static final int SERVER_PORT = 1234;
    public static final int CLIENT_PORT = 1237;
    public static final String LOCALHOST = "localhost";  //"172.28.0.4";
    public static final String SERVERHOST = "localhost"; //"172.28.0.5";
    public static final String QUIT = "quit";

    public static void main(String[] argv) throws Exception {
        String clientSentence = "";
        Scanner inFromUser = new Scanner(System.in);
        Socket clientSocket = new Socket(SERVERHOST, SERVER_PORT);
        DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
        BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        while (true) {
            String input= inFromUser.nextLine();
            if(input.equalsIgnoreCase("quit")){
                clientSocket.close();
                outToServer.close();
                inFromServer.close();
                inFromUser.close();
            return; }
            clientSentence = "GET "+input+ " HTTP/1.1";
            outToServer.writeBytes(clientSentence + "\n");
            String inputLine;
            while ((inputLine = inFromServer.readLine()).length()>0) System.out.println(inputLine);
        }

    }
}

