import Utils.DTLSOverDatagram;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;

class UDPClient {
    public static final int SERVER_PORT = 1234;
    public static final int CLIENT_PORT = 1236;
    public static final String QUIT = "quit";

    public static final String LOCALHOST = "127.0.0.1";//"172.28.0.5";
    private static final int BUFFER_SIZE = 1024;

    public static void main(String[] args) throws Exception {
        Scanner inFromUser = new Scanner(System.in);
        DatagramSocket clientSocket = new DatagramSocket(CLIENT_PORT);
        InetAddress IPAddress = InetAddress.getByName(LOCALHOST);
        while (true) {
            //send
            String input = inFromUser.nextLine();
            byte [] path = ("GET " + input + " HTTP/1.1").getBytes();
            DatagramPacket sendPacket = new DatagramPacket(path, path.length, IPAddress, SERVER_PORT);
            clientSocket.send(sendPacket);
            //receive
            byte[] receiveData = new byte[clientSocket.getReceiveBufferSize()];
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            clientSocket.receive(receivePacket);
            String receivedPacket = new String(receivePacket.getData());
            System.out.println("FROM SERVER:" + receivedPacket);
        }
    }
    private static SSLEngine dtlsSecure(DatagramSocket socket, InetSocketAddress isa, DTLSOverDatagram dtls) throws Exception {
        SSLEngine engine = dtls.createSSLEngine(true);
        dtls.handshake(engine, socket, isa, "Client");
        return engine;
    }
}