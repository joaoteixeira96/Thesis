import Utils.DTLSOverDatagram;
import sun.security.util.HexDumpEncoder;

import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TIRMMRT {
    public static final int PORT = 1234;
    public static final String PASSWORD = "password";
    private static int MAX_APP_READ_LOOPS = 60;
    public static final String KEYSTORE_KEY = "./src/keystore/tirmmrt.key";
    private static final int BUFFER_SIZE = 1024;


    public static void main(String[] args) {
        //TODO - create thread for each socket connection with binding port

        // TCP
        new Thread(() -> {
            ExecutorService executor = null;
            try (ServerSocket server = (args.length == 0) ? new ServerSocket(PORT) : getSecureSocket()) {
                executor = Executors.newFixedThreadPool(5);
                System.out.println("Listening on TCP port " + PORT + ", waiting for file request!");
                while (true) {
                    final Socket socket = server.accept();
                    System.out.println("TCP connection " + socket.getInetAddress() + ":" + socket.getPort());
                    executor.execute(() -> {
                        ClassServer cs = new ClassServer(socket);
                        cs.execTCP();
                    });
                }
            } catch (IOException ioe) {
                System.err.println("Cannot open the port on TCP");
                ioe.printStackTrace();
            } finally {
                System.out.println("Closing TCP server");
                if (executor != null) {
                    executor.shutdown();
                }
            }
        }).start();

        // UDP
        new Thread(() -> {
            try (DatagramSocket socket = new DatagramSocket(PORT)) {
                System.out.println("Listening on UDP port " + PORT + ", waiting for file request!");
                while (true) {
                    if ((args.length == 0)) {
                        byte[] buf = new byte[socket.getReceiveBufferSize()];
                        DatagramPacket packet = new DatagramPacket(buf, buf.length);
                        doUDP(socket, packet, buf);
                    } else {
                        doDTLS(socket);
                    }
                }
            } catch (IOException ioe) {
                System.err.println("Cannot open the port on UDP");
                ioe.printStackTrace();
            } finally {
                System.out.println("Closing UDP server");
            }
        }).start();
    }

    private static ServerSocket getSecureSocket() throws IOException {
        ServerSocketFactory ssf = getServerSocketFactory();
        ServerSocket ss = ssf.createServerSocket(PORT);
        return ss;
    }

    private static void doUDP(DatagramSocket socket, DatagramPacket packet, byte[] buf) throws IOException {
        socket.receive(packet);
        String filePath = new String(buf, StandardCharsets.UTF_8);
        System.out.println(packet.getSocketAddress().toString()
                + ": " + filePath);
        ClassServer cs = new ClassServer();
        packet.setData(cs.execUDP(filePath));
        socket.send(packet);
    }
    

    private static void doDTLS(DatagramSocket socket) {
        try {
            DTLSOverDatagram dtls = new DTLSOverDatagram();
            SSLEngine engine = dtls.createSSLEngine(false);
            InetSocketAddress isa = dtls.handshake(engine, socket, null, "Server");
            ByteBuffer fileData = receiveAppData(engine, socket);
            deliverAppData(dtls, engine, socket, fileData, isa);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Unable to do DTLS");
        }

    }

    private static ServerSocketFactory getServerSocketFactory() {

        SSLServerSocketFactory ssf = null;
        try {
            // set up key manager to do server authentication
            SSLContext ctx;
            KeyManagerFactory kmf;
            KeyStore ks;
            char[] passphrase = PASSWORD.toCharArray();

            ctx = SSLContext.getInstance("TLS");
            kmf = KeyManagerFactory.getInstance("SunX509");
            ks = KeyStore.getInstance("JKS");

            ks.load(new FileInputStream(KEYSTORE_KEY), passphrase);
            kmf.init(ks, passphrase);
            ctx.init(kmf.getKeyManagers(), null, null);

            ssf = ctx.getServerSocketFactory();
            return ssf;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SSLEngine doDTLSHandshake(DTLSOverDatagram dtls, DatagramSocket socket, InetSocketAddress isa) throws Exception {
        SSLEngine engine = dtls.createSSLEngine(false);
        dtls.handshake(engine, socket, isa, "Server");
        return engine;
    }

    public static ByteBuffer receiveAppData(SSLEngine engine,
                                            DatagramSocket socket) throws Exception {
        ByteBuffer recBuffer = null;
        int loops = MAX_APP_READ_LOOPS;
        while (true) {
            if (--loops < 0) {
                throw new RuntimeException(
                        "Too much loops to receive application data");
            }
            byte[] buf = new byte[BUFFER_SIZE];
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);
            ByteBuffer netBuffer = ByteBuffer.wrap(buf, 0, packet.getLength());
            recBuffer = ByteBuffer.allocate(BUFFER_SIZE);
            SSLEngineResult rs = engine.unwrap(netBuffer, recBuffer);
            recBuffer.flip();
            if (recBuffer.remaining() != 0) {
                printHex("Received application data", recBuffer);
                ClassServer cs = new ClassServer();
                return ByteBuffer.wrap(cs.execUDP(new String(recBuffer.array(), StandardCharsets.UTF_8)));
                //break;
            }
        }
    }

    static void deliverAppData(DTLSOverDatagram dtls, SSLEngine engine, DatagramSocket socket,
                               ByteBuffer appData, SocketAddress peerAddr) throws Exception {

        // Note: have not consider the packet loses
        List<DatagramPacket> packets =
                dtls.produceApplicationPackets(engine, appData, peerAddr);
        appData.flip();
        for (DatagramPacket p : packets) {
            socket.send(p);
        }
    }

    public final static void printHex(String prefix, ByteBuffer bb) {
        HexDumpEncoder dump = new HexDumpEncoder();

        synchronized (System.out) {
            System.out.println(prefix);
            try {
                dump.encodeBuffer(bb.slice(), System.out);
            } catch (Exception e) {
                // ignore
            }
            System.out.flush();
        }
    }
}