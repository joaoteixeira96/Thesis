import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

class UDPClient {
    public static final int SERVER_PORT = 1234;
    public static final int CLIENT_PORT = 1236;
    public static final String QUIT = "quit";

    public static final String LOCALHOST = "172.28.0.5";

    public static void main(String[] args) throws Exception {
        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
        DatagramSocket clientSocket = new DatagramSocket(CLIENT_PORT);
        InetAddress IPAddress = InetAddress.getByName(LOCALHOST);
        byte[] sendData;
        byte[] receiveData = new byte[1024];
        String sentence = "";
        while (!sentence.equalsIgnoreCase(QUIT)) {
            sentence = inFromUser.readLine();
            sendData = sentence.getBytes();
            DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, SERVER_PORT);
            clientSocket.send(sendPacket);
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            clientSocket.receive(receivePacket);
            String modifiedSentence = new String(receivePacket.getData());
            System.out.println("FROM SERVER "+ receivePacket.getSocketAddress() +": " + modifiedSentence);
        }
        inFromUser.close();
        clientSocket.close();
    }
}