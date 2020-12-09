package com.joaoteixeira;

import Utils.DTLSOverDatagram;
import Utils.Http;
import org.apache.http.HttpHost;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;

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
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TIRMMRT {
    public static final int PORT = 1234;
    public static final String PASSWORD = "password";
    public static final int BUF_SIZE = 1024;
    public static final String KEYSTORE_KEY = "./src/main/java/keystore/tirmmrt.key";
    public static final String REMOTE_HOST = "172.28.0.6";
    public static final int REMOTE_PORT = 1238;
    public static final String TOR_HOST = "172.28.0.5";
    public static final int TOR_PORT = 9050;


    public static void main(String[] args) throws IOException {
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
                    executor.execute(() -> doTCP_TLS(socket));
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
            } catch (IOException | InterruptedException ioe) {
                System.err.println("Cannot open the port on UDP");
                ioe.printStackTrace();
            } finally {
                System.out.println("Closing UDP server");
            }
        }).start();
    }

    //TIR-MMRT directly requests HttpServer without going throw Tor
    private static byte[] httpRequest(String path) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Socket socket = new Socket(REMOTE_HOST, REMOTE_PORT);
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        String request = String.format(
                "GET %s HTTP/1.1\r\n" +
                        "Host: %s\r\n" +
                        "User-Agent: X-com.joaoteixeira.TIRMMRT\r\n\r\n", path, REMOTE_HOST);

        out.write(request.getBytes());

        System.out.println("\nSent Request:\n" + request);
        System.out.println("Got Reply:\n");
        System.out.println("\nReply Header:\n");

        baos.write(("\nSent Request:\n\n" + request).getBytes());
        baos.write(("Got Reply:\n").getBytes());
        baos.write(("\nReply Header:\n").getBytes());

        String answerLine = Http.readLine(in);  // first line is always present
        System.out.println(answerLine);
        baos.write((answerLine + "\r\n").getBytes());
        String[] reply = Http.parseHttpReply(answerLine);

        answerLine = Http.readLine(in);
        while (!answerLine.equals("")) {
            System.out.println(answerLine);
            baos.write((answerLine + "\r\n").getBytes());
            answerLine = Http.readLine(in);
        }

        if (reply[1].equals("200")) {

            System.out.println("\r\nReply Body:\n");
            baos.write(("\r\nReply Body:\n").getBytes());
            long time0 = System.currentTimeMillis();
            int n;
            byte[] buffer = new byte[BUF_SIZE];

            while ((n = in.read(buffer)) >= 0) {
                System.out.write(buffer, 0, n);
                baos.write(buffer, 0, n);
            }
        } else {
            System.out.println("Ooops, received status:" + reply[1]);
            baos.write(("Ooops, received status:" + reply[1] + "\n").getBytes());
        }
        baos.write("\n".getBytes());
        socket.close();
        baos.close();
        return baos.toByteArray();
    }

    private static void doTCP_TLS(Socket socket) {
        try {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            while (true) {
                byte[] buffer = new byte[socket.getReceiveBufferSize()];
                in.read(buffer);
                String filePath = new String(buffer);
                System.out.println("File request path: " + filePath + " from " + socket.getInetAddress() + ":" + socket.getPort());
                //byte[] data = httpRequest(filePath);
                byte[] data = torRequest(filePath);
                out.write(data, 0, data.length);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static ServerSocket getSecureSocketTLS() throws IOException {
        ServerSocketFactory ssf = getServerSocketFactory();
        ServerSocket ss = ssf.createServerSocket(PORT);
        return ss;
    }

    private static void doUDP(DatagramSocket socket) throws IOException, InterruptedException {
        //receive
        byte[] buf = new byte[socket.getReceiveBufferSize()];
        DatagramPacket receivePacket = new DatagramPacket(buf, buf.length);
        socket.receive(receivePacket);
        String filePath = new String(buf, StandardCharsets.UTF_8);
        System.out.println("File request path: " + filePath + " from " + receivePacket.getAddress() + ":" + receivePacket.getPort());
        byte[] data = torRequest(filePath);
        //send
        int bytesSent = 0;
        while (bytesSent <= data.length) {
            byte[] sendData = Arrays.copyOfRange(data, bytesSent, bytesSent + BUF_SIZE);
            DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, receivePacket.getAddress(), receivePacket.getPort());
            socket.send(sendPacket);
            bytesSent += BUF_SIZE;
            socket.receive(sendPacket); //Important to make UDP flow traffic
        }
    }


    private static void doDTLS(DatagramSocket socket) {
        try {
            DTLSOverDatagram dtls = new DTLSOverDatagram();
            SSLEngine engine = dtls.createSSLEngine(false);
            InetSocketAddress isa = dtls.handshake(engine, socket, null, "Server");
            String filePath = dtls.receiveAppData(engine, socket);
            byte[] data = torRequest(filePath);
            dtls.deliverAppData(engine, socket, ByteBuffer.wrap(data), isa);

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Unable to do DTLS");
        }

    }

    private static ServerSocketFactory getServerSocketFactory() {

        SSLServerSocketFactory ssf;
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

    private static byte[] torRequest(String path) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Registry<ConnectionSocketFactory> reg = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.INSTANCE)
                .register("https", new MyConnectionSocketFactory(SSLContexts.createSystemDefault())) //Only used to very if Tor is working correctly
                .build();
        PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager(reg);
        try (CloseableHttpClient httpclient = HttpClients.custom()
                .setConnectionManager(cm)
                .build()) {
            InetSocketAddress socksaddr = new InetSocketAddress(TOR_HOST, TOR_PORT);
            HttpClientContext context = HttpClientContext.create();
            context.setAttribute("socks.address", socksaddr);

            //HttpHost target = new HttpHost("check.torproject.org", 80, "http");
            HttpHost target = new HttpHost(REMOTE_HOST, REMOTE_PORT, "http");
            HttpGet request = new HttpGet(path.trim());
            System.err.println("Requesting Tor path:" + path);

            try (CloseableHttpResponse response = httpclient.execute(target, request, context)) {
                System.out.println(response.getStatusLine());
                baos.write((response.getStatusLine() + "\r\n").getBytes());
                Arrays.stream(response.getAllHeaders()).forEach(System.out::println);
                Arrays.stream(response.getAllHeaders()).forEach(header -> {
                    try {
                        baos.write((header + "\r\n").getBytes());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
                baos.write("\r\n".getBytes()); //Separate line between header and body
                int n;
                byte[] buffer = new byte[BUF_SIZE];
                while ((n = response.getEntity().getContent().read(buffer, 0, buffer.length)) >= 0) {
                    baos.write(buffer, 0, n);
                    System.out.write(buffer, 0, n);
                }
                EntityUtils.consume(response.getEntity());
            }
        }
        return baos.toByteArray();
    }

    static class MyConnectionSocketFactory extends SSLConnectionSocketFactory {

        public MyConnectionSocketFactory(final SSLContext sslContext) {
            super(sslContext);
        }

        @Override
        public Socket createSocket(final HttpContext context) throws IOException {
            InetSocketAddress socksaddr = (InetSocketAddress) context.getAttribute("socks.address");
            Proxy proxy = new Proxy(Proxy.Type.SOCKS, socksaddr);
            return new Socket(proxy);
        }

    }
}