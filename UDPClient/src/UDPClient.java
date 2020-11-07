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
    private static final int MAX_APP_READ_LOOPS = 10;

    public static void main(String[] args) throws Exception {
        Scanner inFromUser = new Scanner(System.in);
        DatagramSocket clientSocket = new DatagramSocket(CLIENT_PORT);
        InetAddress IPAddress = InetAddress.getByName(LOCALHOST);
        byte[] path;

        //Initialize
        DTLSOverDatagram dtls = new DTLSOverDatagram();
        DatagramPacket initializePacketSend = new DatagramPacket(new byte[BUFFER_SIZE], BUFFER_SIZE, IPAddress, SERVER_PORT);
        clientSocket.send(initializePacketSend);
        InetSocketAddress isa = new InetSocketAddress(initializePacketSend.getAddress(), initializePacketSend.getPort());
        SSLEngine engine = dtlsSecure(clientSocket, isa, dtls);

        while (true) {
            String input = inFromUser.nextLine();
            path = ("GET " + input + " HTTP/1.1").getBytes();

            //send
            ByteBuffer bf = ByteBuffer.wrap(path,0,path.length);

            List<DatagramPacket> packets =
                    dtls.produceApplicationPackets(engine, bf, isa);
            bf.flip();
            for (DatagramPacket p : packets) {
                clientSocket.send(p);
            }

            //receive
                byte[] buf = new byte[BUFFER_SIZE];
                DatagramPacket receivePacket = new DatagramPacket(buf, buf.length);
                clientSocket.receive(receivePacket);

                ByteBuffer netBuffer = ByteBuffer.wrap(buf, 0, receivePacket.getLength());
                ByteBuffer recBuffer = ByteBuffer.allocate(BUFFER_SIZE);

                SSLEngineResult rs = engine.unwrap(netBuffer, recBuffer);
                recBuffer.flip();
                System.out.println(rs.getStatus());
                if (recBuffer.remaining() != 0) {
                    //dtls.printHex("File request path: ", recBuffer);
                    System.out.println(new String(recBuffer.array()));
                }




            //socket.receive(packet);
            //System.out.println("UDP: " + packet.getSocketAddress().toString()
            //        + ": " + new String(buf, StandardCharsets.UTF_8));
            // Echo server
            // Note: have not consider the packet loses
            //socket.send(packet);

        }
    }
    private static SSLEngine dtlsSecure(DatagramSocket socket, InetSocketAddress isa, DTLSOverDatagram dtls) throws Exception {
        SSLEngine engine = dtls.createSSLEngine(true);
        dtls.handshake(engine, socket, isa, "Client");
        return engine;
    }
}