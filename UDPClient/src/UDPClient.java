import Utils.DTLSOverDatagram;
import sun.security.util.HexDumpEncoder;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Scanner;

class UDPClient {
    public static final int REMOTE_PORT = 1234;
    public static final int LOCAL_PORT = 1236;

    public static final String REMOTE_HOST = "127.0.0.1";//"172.28.0.5";

    public static void main(String[] args) throws Exception {
        Scanner inFromUser = new Scanner(System.in);
        DatagramSocket clientSocket = new DatagramSocket(LOCAL_PORT);
        InetAddress IPAddress = InetAddress.getByName(REMOTE_HOST);
        while (true) {
            //send
            String input = inFromUser.nextLine();
            byte [] path = ("GET " + input + " HTTP/1.1").getBytes();
            if ((args.length == 0)) {
                doUDP(path, IPAddress, clientSocket);
            } else {
                doDTLS(clientSocket, path);
            }
        }
    }
    private static void doUDP(byte [] path, InetAddress IPAddress, DatagramSocket clientSocket){
        try{
            DatagramPacket sendPacket = new DatagramPacket(path, path.length, IPAddress, REMOTE_PORT);
            clientSocket.send(sendPacket);
            //receive
            byte[] receiveData = new byte[clientSocket.getReceiveBufferSize()];
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            clientSocket.receive(receivePacket);
            String receivedPacket = new String(receivePacket.getData());
            System.out.println("FROM SERVER:" + receivedPacket);
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Unable to do UDP");
        }
    }
    private static void doDTLS(DatagramSocket socket, byte[] filePath){
        try {
            DTLSOverDatagram dtls = new DTLSOverDatagram();
            InetSocketAddress isa = new InetSocketAddress(REMOTE_HOST, REMOTE_PORT);

            SSLEngine engine = doDTLSHandshake(socket,isa,dtls);

            dtls.deliverAppData(engine, socket, ByteBuffer.wrap(filePath), isa);
            dtls.receiveAppData(engine, socket);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Unable to do DTLS");
        }
    }
    private static SSLEngine doDTLSHandshake(DatagramSocket socket, InetSocketAddress isa, DTLSOverDatagram dtls) throws Exception {
        SSLEngine engine = dtls.createSSLEngine(true);
        dtls.handshake(engine, socket, isa, "Client");
        return engine;
    }
}