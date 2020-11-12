import Utils.ClassServer;
import Utils.DTLSOverDatagram;

import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Date;
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
            try (ServerSocket server = (args.length == 0) ? new ServerSocket(PORT) : getSecureSocketTLS()) {
                executor = Executors.newFixedThreadPool(5);
                System.out.println("Listening on TCP port " + PORT + ", waiting for file request!");
                while (true) {
                    final Socket socket = server.accept();
                    System.out.println("TCP connection " + socket.getInetAddress() + ":" + socket.getPort());
                    executor.execute(() -> {
                        doTCP_TLS(socket);
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
                        doUDP(socket);
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

    private static void doTCP_TLS(Socket socket) {
        try {
            OutputStream rawOut = socket.getOutputStream();

            PrintWriter out = new PrintWriter(
                    new BufferedWriter(
                            new OutputStreamWriter(
                                    rawOut)));
            try {
                // get path to class file from header
                BufferedReader in =
                        new BufferedReader(
                                new InputStreamReader(socket.getInputStream()));
                while (true) {
                    String filePath = in.readLine();

                    System.out.println("File request path: " + filePath + " from " + socket.getInetAddress() + ":" + socket.getPort());

                    byte[] fileData = ClassServer.retrieveFile(filePath);

                    // send HTTP Headers
                    out.println("HTTP/1.1 200 OK");
                    out.println("Date: " + new Date());
                    out.println("Content-type: " + getContentType(filePath));
                    out.println("Content-length: " + fileData.length);
                    out.println(); // blank line between headers and content, very important !
                    rawOut.write(fileData, 0, fileData.length);
                    rawOut.flush();
                    out.flush(); // flush character output stream buffer

                }
            } catch (Exception e) {
                e.printStackTrace();
                // write out error response
                out.println("HTTP/1.0 400 " + e.getMessage() + "\r\n");
                out.println("Content-Type: text/html\r\n\r\n");
                out.flush();
            }


        } catch (IOException ex) {
            // eat exception (could log error to log file, but
            // write out to stdout for now).
            System.out.println("error writing response: " + ex.getMessage());
            ex.printStackTrace();

        } finally {
            try {
                socket.close();
            } catch (IOException e) {
            }
        }
    }

    private static ServerSocket getSecureSocketTLS() throws IOException {
        ServerSocketFactory ssf = getServerSocketFactory();
        ServerSocket ss = ssf.createServerSocket(PORT);
        return ss;
    }

    private static void doUDP(DatagramSocket socket) throws IOException {
        byte[] buf = new byte[socket.getReceiveBufferSize()];
        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        socket.receive(packet);
        String filePath = new String(buf, StandardCharsets.UTF_8);
        System.out.println(packet.getSocketAddress().toString()
                + ": " + filePath);
        byte[] sendData = buildRequest(filePath, ClassServer.retrieveFile(filePath), null);
        packet.setData(sendData);
        socket.send(packet);
    }


    private static void doDTLS(DatagramSocket socket) {
        try {
            DTLSOverDatagram dtls = new DTLSOverDatagram();
            SSLEngine engine = dtls.createSSLEngine(false);
            InetSocketAddress isa = dtls.handshake(engine, socket, null, "Server");
            ByteBuffer fileData = dtls.receiveAppData(engine, socket);
            byte[] sendData = buildRequest("", fileData.array(), null);
            dtls.deliverAppData(engine, socket, ByteBuffer.wrap(sendData), isa);

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Unable to do DTLS");
        }

    }

    private static byte[] buildRequest(String filePath, byte[] file, String error) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (error == null) {
            baos.write(("HTTP/1.1 200 OK" + "\r\n").getBytes());
            baos.write(("Date: " + new Date() + "\r\n").getBytes());
            baos.write(("Content-type: " + getContentType(filePath) + "\r\n").getBytes());
            baos.write(("Content-length: " + file.length + "\r\n\r\n").getBytes());
            baos.write(file);
        } else {
            baos.write(("HTTP/1.0 400 " + error + "\r\n").getBytes());
            baos.write(("Content-Type: text/html\r\n\r\n").getBytes());
        }
        return baos.toByteArray();
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

    private static String getContentType(String fileRequested) {
        if (fileRequested.endsWith(".htm") || fileRequested.endsWith(".html"))
            return "text/html";
        else
            return "text/plain";
    }
}