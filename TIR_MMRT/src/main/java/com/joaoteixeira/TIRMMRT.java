package com.joaoteixeira;

import Utils.DTLSOverDatagram;
import Utils.Http;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
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
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class TIRMMRT {

    public static final String PASSWORD = "password";
    public static final String KEYSTORE_KEY = "./keystore/server.key";
    public static final int BUF_SIZE = 1024;

    public static String local_host = "127.0.0.1";
    public static int local_port_unsecure = 1234;
    public static int local_port_secure = 2000;

    public static String remote_host = "localhost"; //172.28.0.6 or 127.0.0.1
    public static int remote_port = 1238;

    public static String tor_host = "127.0.0.1";
    public static int tor_port = 9050;

    public static int bypass_timer = 0;
    public static String bypassAddress = null;

    public static List<String> tirmmrt_network = null;

    public static String strategy;

    public static String stunnel_port = "1239";


    public static void main(String[] args) throws FileNotFoundException {
        System.setProperty("javax.net.ssl.trustStore", "./keystore/servers");
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);

        readConfigurationFiles();
        bypassTriggeredTimer();

        // TCP
        new Thread(() -> {
            ExecutorService executor = null;
            try (ServerSocket server = new ServerSocket(local_port_unsecure)) {
                executor = Executors.newFixedThreadPool(5);
                System.out.println("Listening on TCP port " + local_port_unsecure + ", waiting for file request!");
                while (true) {
                    final Socket socket = server.accept();
                    System.out.println("TCP connection " + socket.getInetAddress() + ":" + socket.getPort());
                    executor.execute(() -> doTCP_TLS(socket));
                }
            } catch (IOException ioe) {
                System.err.println("Cannot open the port on TCP");
                ioe.printStackTrace();
            } finally {
                System.out.println("Closing TCP server.key");
                if (executor != null) {
                    executor.shutdown();
                }
            }
        }).start();

        // TLS
        new Thread(() -> {
            ExecutorService executor = null;
            try (ServerSocket server = getSecureSocketTLS(local_port_secure)) {
                executor = Executors.newFixedThreadPool(5);
                System.out.println("Listening on TLS port " + local_port_secure + ", waiting for file request!");
                while (true) {
                    final Socket socket = server.accept();
                    System.out.println("TLS connection " + socket.getInetAddress() + ":" + socket.getPort());
                    executor.execute(() -> doTCP_TLS(socket));
                }
            } catch (IOException ioe) {
                System.err.println("Cannot open the port on TLS");
                ioe.printStackTrace();
            } finally {
                System.out.println("Closing TLS server");
                if (executor != null) {
                    executor.shutdown();
                }
            }
        }).start();

        // UDP
        new Thread(() -> {
            try (DatagramSocket socket = new DatagramSocket(local_port_unsecure)) {
                System.out.println("Listening on UDP port " + local_port_unsecure + ", waiting for file request!");
                while (true) {
                    doUDP(socket);
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.err.println("Cannot open the port on UDP");

            } finally {
                System.out.println("Closing UDP server");
            }
        }).start();

        //DTLS
        new Thread(() -> {
            try (DatagramSocket socket = new DatagramSocket(local_port_secure)) {
                System.out.println("Listening on DTLS port " + local_port_secure + ", waiting for file request!");
                while (true) {
                    doDTLS(socket);
                }
            } catch (Exception e) {
                e.printStackTrace();
                System.err.println("Cannot open the port on DTLS");

            } finally {
                System.out.println("Closing DTLS server");
            }
        }).start();

    }

    private static void doTCP_TLS(Socket socket) {
        try {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[socket.getReceiveBufferSize()];
            in.read(buffer);
            String filePath = Http.parseHttpReply(new String(buffer))[1];
            System.out.println("File request path: " + filePath + " from " + socket.getInetAddress() + ":" + socket.getPort());
            byte[] data = bypass(filePath);
            out.write(data, 0, data.length);
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static ServerSocket getSecureSocketTLS(int port) throws IOException {
        ServerSocketFactory ssf = getServerSocketFactory();
        ServerSocket ss = ssf.createServerSocket(port);
        return ss;
    }

    private static void doUDP(DatagramSocket socket) throws Exception {
        //receive
        byte[] buf = new byte[socket.getReceiveBufferSize()];
        DatagramPacket receivePacket = new DatagramPacket(buf, buf.length);
        socket.receive(receivePacket);
        System.out.println("UDP connection " + socket.getInetAddress() + ":" + socket.getPort());
        String filePath = new String(buf, StandardCharsets.UTF_8);
        System.out.println("File request path: " + filePath + " from " + receivePacket.getAddress() + ":" + receivePacket.getPort());
        byte[] data = bypass(filePath);
        //send
        int bytesSent = 0;
        while (bytesSent <= data.length) {
            byte[] sendData = Arrays.copyOfRange(data, bytesSent, bytesSent + BUF_SIZE); //prevent sending bytes overflow
            DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, receivePacket.getAddress(), receivePacket.getPort());
            socket.send(sendPacket);
            socket.receive(sendPacket);
            bytesSent += BUF_SIZE;
        }
        byte[] endTransmission = "terminate_packet_receive".getBytes();
        socket.send(new DatagramPacket(endTransmission, endTransmission.length, receivePacket.getAddress(), receivePacket.getPort()));
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

    private static void readConfigurationFiles() throws FileNotFoundException {
        tirmmrt_network = new ArrayList<>();

        try (InputStream input = new FileInputStream("./configuration/config.properties")) {
            Properties prop = new Properties();

            prop.load(input);

            local_host = prop.getProperty("local_host");
            local_port_unsecure = Integer.parseInt(prop.getProperty("local_port_unsecure"));
            local_port_secure = Integer.parseInt(prop.getProperty("local_port_secure"));
            remote_host = prop.getProperty("remote_host");
            remote_port = Integer.parseInt(prop.getProperty("remote_port"));
            tor_host = prop.getProperty("tor_host");
            tor_port = Integer.parseInt(prop.getProperty("tor_port"));
            stunnel_port = prop.getProperty("stunnel_port");
            strategy = prop.getProperty("strategy");
            bypass_timer = Integer.parseInt(prop.getProperty("bypass_timer"));

        } catch (IOException e) {
            e.printStackTrace();
        }
        File file = new File("./configuration/TIR-MMRT_network");
        Scanner sc = new Scanner(file);
        while (sc.hasNextLine())
            tirmmrt_network.add(sc.nextLine());
        sc.close();
    }

    private static void randomlyChooseBypassAddress() {
        bypassAddress = tirmmrt_network.get(new Random().nextInt(tirmmrt_network.size()));
        System.err.println("Selected new bypass address is " + bypassAddress);
    }

    private static void bypassTriggeredTimer() {
        Timer timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                randomlyChooseBypassAddress();
            }
        }, 0, bypass_timer);
    }

    private static byte[] bypass(String path) throws Exception {
        String my_address = local_host + ":" + local_port_unsecure;
        if (bypassAddress.equals(my_address)) {
            return torRequest(path);
        } else {
            System.err.println("TIR-MMRT connection :" + my_address + " ---> " + bypassAddress);
            return bypassConnection(path);
        }
    }

    private static byte[] bypassConnection(String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("./keystore/server.key"), PASSWORD.toCharArray());

        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(keyStore, PASSWORD.toCharArray())
                .build();

        HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        HttpResponse response = httpClient.execute(new HttpGet("https://localhost:" + stunnel_port + path.trim()));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Arrays.stream(response.getAllHeaders()).forEach(header -> {
            try {
                baos.write((header + "\r\n").getBytes());
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        baos.write("\r\n".getBytes()); //Separate line between header and body
        baos.write(response.getEntity().getContent().readAllBytes());
        byte[] out = baos.toByteArray();
        System.out.println(new String(out));
        return out;
    }

    private static ServerSocketFactory getServerSocketFactory() {

        SSLServerSocketFactory ssf;
        try {
            // set up key manager to do server.key authentication
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
            InetSocketAddress socksaddr = new InetSocketAddress(tor_host, tor_port);
            HttpClientContext context = HttpClientContext.create();
            context.setAttribute("socks.address", socksaddr);

            //HttpHost target = new HttpHost("check.torproject.org", 80, "http");
            HttpHost target = new HttpHost(remote_host, remote_port, "http");
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