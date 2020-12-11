import Utils.DTLSOverDatagram;
import Utils.Stats;
import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Scanner;

class UDPClient {
    public static final int REMOTE_PORT = 1234;
    public static final int LOCAL_PORT = 1236;

    public static final String REMOTE_HOST = "127.0.0.1";//"172.28.0.5 or 127.0.0.1";
    public static final int BUF_SIZE = 1024;

    public static void main(String[] args) throws Exception {
        Scanner inFromUser = new Scanner(System.in);
        InetAddress IPAddress = InetAddress.getByName(REMOTE_HOST);
        while (true) {
            DatagramSocket clientSocket = new DatagramSocket(LOCAL_PORT);
            //send
            String input = inFromUser.nextLine();
            byte [] path = input.getBytes();
            if ((args.length == 0)) {
                doUDP(path, IPAddress, clientSocket);
            } else {
                doDTLS(clientSocket, path);
            }
            clientSocket.close();
        }
    }
    private static void doUDP(byte [] path, InetAddress IPAddress, DatagramSocket clientSocket){
        try{
            Stats stats = new Stats();
            DatagramPacket sendPacket = new DatagramPacket(path, path.length, IPAddress, REMOTE_PORT);
            clientSocket.send(sendPacket);
            //receive
            byte[] sendData = new byte[BUF_SIZE];
            DatagramPacket receivedPacket = new DatagramPacket(sendData, sendData.length);
            clientSocket.receive(receivedPacket);
            int contentLength = getContentLength(sendData);
            while (true) {
                stats.newRequest(receivedPacket.getLength());
                contentLength -= receivedPacket.getLength();
                System.out.println(new String(receivedPacket.getData()));
                clientSocket.send(sendPacket); //Important to make UDP flow traffic
                if(contentLength<0) break;
                clientSocket.receive(receivedPacket);
            }
            stats.printReport();
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
    private static int getContentLength(byte[] data) {
        String s = new String(data);
        try {
            String[] strArr = s.split("Content-Length: ");
            if (strArr.length > 1) {
                strArr = strArr[1].split(" ");
                return Integer.parseInt(strArr[0]);
            }
        } catch (Exception e) {
            return 0;
        }
        return 0;
    }
}