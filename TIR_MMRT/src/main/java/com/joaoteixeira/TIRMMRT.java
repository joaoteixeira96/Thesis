package com.joaoteixeira;

import Utils.DTLSOverDatagram;
import Utils.Http;
import com.msopentech.thali.java.toronionproxy.Utilities;

import javax.net.ServerSocketFactory;
import javax.net.ssl.*;
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
    public static final String KEYSTORE_KEY = "./keystore/tirmmrt.key";
    public static final int BUF_SIZE = 1024;
    public static final int N_THREADS = 8;
    public static final int secureHttpingRequestPort = 2238;

    public static String local_host;
    public static int local_port_unsecure;
    public static int local_port_secure;

    public static String remote_host;
    public static int remote_port;

    public static String tor_host;
    public static int tor_port;

    public static int bypass_timer;
    public static String bypassAddress;

    public static List<String> tirmmrt_network;

    public static String stunnel_port;

    public static int tor_buffer_size;
    public static int test_port_iperf;
    public static int test_stunnel_port_iperf;

    public static int test_port_httping;
    public static int test_stunnel_port_httping;

    public static int number_of_tirmmrt;


    public static void main(String[] args) throws FileNotFoundException {
        System.setProperty("javax.net.ssl.trustStore", "./keystore/tirmmrts");
        System.setProperty("javax.net.ssl.trustStorePassword", PASSWORD);

        readConfigurationFiles();
        bypassTriggeredTimer();


        // TCP
        new Thread(() -> {
            ExecutorService executor = null;
            try (ServerSocket server = new ServerSocket(local_port_unsecure)) {
                executor = Executors.newFixedThreadPool(N_THREADS);
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
                System.out.println("Closing TCP server");
                if (executor != null) {
                    executor.shutdown();
                }
            }
        }).start();

        // TLS
        new Thread(() -> {
            ExecutorService executor = null;
            try (ServerSocket server = getSecureSocketTLS(local_port_secure)) {
                executor = Executors.newFixedThreadPool(N_THREADS);
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

        // Iperf test
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(test_port_iperf)) {

                System.out.println("Iperf proxy is listening on port " + test_port_iperf);

                while (true) {
                    Socket socket = serverSocket.accept();
                    measureTestIperf(socket);
                    socket.close();
                }

            } catch (IOException ex) {
                System.out.println("Iperf exception: " + ex.getMessage());
                ex.printStackTrace();
            }
        }).start();

        // HTTPing test
        new Thread(() -> {
            ExecutorService executor = null;
            try (ServerSocket ss = new ServerSocket(test_port_httping)) {
                executor = Executors.newFixedThreadPool(N_THREADS);
                System.out.println("Httping proxy is listening on port " + test_port_httping);
                while (true) {
                    Socket clientSock = ss.accept();
                    measureTestHttping(clientSock);
                    clientSock.close();
                }
            } catch (IOException ioe) {
                System.err.println("Cannot open the port on Httping");
                ioe.printStackTrace();
            } finally {
                System.out.println("Closing Httping server");
                if (executor != null) {
                    executor.shutdown();
                }
            }
        }).start();
    }

    private static void measureTestHttping(Socket socket) {
        try {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            byte[] buffer = new byte[tor_buffer_size];
            String my_address = local_host;

            if (bypassAddress.equals(my_address)) {

                OutputStream outTor;
                InputStream inTor;
                Socket socketTor;

                while ((in.read(buffer, 0, buffer.length)) != -1) {
                    System.err.println("Sending to iperf: " + new String(buffer));
                    out.write(buffer, 0, buffer.length);
                }
                byte[] bufferTor = new byte[tor_buffer_size];
                in.read(buffer, 0, buffer.length);

                if (new String(buffer).contains("https")) {
                    socketTor = Utilities.socks4aSocketConnection(remote_host, secureHttpingRequestPort, tor_host, tor_port);
                } else {
                    socketTor = Utilities.socks4aSocketConnection(remote_host, remote_port, tor_host, tor_port);
                }
                outTor = socketTor.getOutputStream();
                outTor.flush();
                inTor = socketTor.getInputStream();

                System.err.println("Sending to httping: " + new String(buffer));
                outTor.write(buffer, 0, buffer.length);
                inTor.read(bufferTor);
                out.write(bufferTor);
                outTor.flush();

                socketTor.close();
            } else {
                System.err.println("TIR-MMRT test connection :" + my_address + " ---> " + bypassAddress);

                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket socketStunnel = (SSLSocket) factory.createSocket(bypassAddress.split(":")[0], test_stunnel_port_httping);
                socketStunnel.startHandshake();
                OutputStream outStunnel = socketStunnel.getOutputStream();
                InputStream inStunnel = socketStunnel.getInputStream();

                byte[] bufferTStunnel = new byte[tor_buffer_size];
                in.read(buffer, 0, buffer.length);
                System.err.println("Received from httping: " + new String(buffer));
                outStunnel.write(buffer, 0, buffer.length);
                inStunnel.read(bufferTStunnel);
                out.write(bufferTStunnel);

                out.flush();
                outStunnel.flush();
                socketStunnel.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }


    private static void measureTestIperf(Socket serverSocket) {
        try {
            InputStream in = serverSocket.getInputStream();

            byte[] buffer = new byte[tor_buffer_size];
            String my_address = local_host;

            if (bypassAddress.equals(my_address)) {

                Socket clientSocket = Utilities.socks4aSocketConnection(remote_host, 5001, tor_host, tor_port);

                OutputStream out = clientSocket.getOutputStream();
                out.flush();

                while ((in.read(buffer, 0, buffer.length)) != -1) {
                    System.err.println("Sending to iperf: " + new String(buffer));
                    out.write(buffer, 0, buffer.length);
                }
                out.flush();
                clientSocket.close();

            } else {
                System.err.println("TIR-MMRT test connection :" + my_address + " ---> " + bypassAddress);

                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket socket = (SSLSocket) factory.createSocket(bypassAddress.split(":")[0], test_stunnel_port_iperf);
                socket.startHandshake();
                OutputStream out = socket.getOutputStream();

                while ((in.read(buffer, 0, buffer.length)) != -1) {
                    System.err.println("Received from iperf: " + new String(buffer));
                    out.write(buffer, 0, buffer.length);
                }
                out.flush();
                socket.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }


    private static ServerSocket getSecureSocketTLS(int port) throws IOException {
        ServerSocketFactory ssf = getServerSocketFactory();
        ServerSocket ss = ssf.createServerSocket(port);
        return ss;
    }

    private static void doTCP_TLS(Socket socket) {
        try {
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[BUF_SIZE];
            in.read(buffer);
            String filePath = Http.parseHttpReply(new String(buffer))[1];
            System.out.println("File request path: " + filePath + " from " + socket.getInetAddress() + ":" + socket.getPort());
            byte[] data = bypass(filePath);
            out.write(data, 0, data.length);
            out.flush();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void doUDP(DatagramSocket socket) throws Exception {
        //receive
        byte[] buf = new byte[socket.getReceiveBufferSize()];
        DatagramPacket receivePacket = new DatagramPacket(buf, buf.length);
        socket.receive(receivePacket);
        String filePath = new String(buf, StandardCharsets.UTF_8);
        System.out.println("File request path: " + filePath + " from " + receivePacket.getAddress() + ":" + receivePacket.getPort());
        byte[] data = bypass(filePath);

        //send
        ExecutorService executor;
        executor = Executors.newFixedThreadPool(N_THREADS);
        executor.execute(() -> {
            try {
                int bytesSent = 0;
                while (bytesSent <= data.length) {
                    byte[] sendData = Arrays.copyOfRange(data, bytesSent, bytesSent + BUF_SIZE); //prevent sending bytes overflow
                    DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, receivePacket.getAddress(), receivePacket.getPort());
                    socket.send(sendPacket);
                    bytesSent += BUF_SIZE;
                    Thread.sleep(1); //For big files
                }
                byte[] endTransmission = "terminate_packet_receive".getBytes();
                socket.send(new DatagramPacket(endTransmission, endTransmission.length, receivePacket.getAddress(), receivePacket.getPort()));
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }


    private static void doDTLS(DatagramSocket socket) {
        try {
            //Handshake and receive
            DTLSOverDatagram dtls = new DTLSOverDatagram();
            SSLEngine engine = dtls.createSSLEngine(false);
            InetSocketAddress isa = dtls.handshake(engine, socket, null, "Server");
            String filePath = dtls.receiveAppData(engine, socket);
            byte[] data = bypass(filePath);
            //deliver up to nThread clients
            ExecutorService executor = null;
            executor = Executors.newFixedThreadPool(N_THREADS);
            executor.execute(() -> dtls.deliverAppData(engine, socket, ByteBuffer.wrap(data), isa));

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
            bypass_timer = Integer.parseInt(prop.getProperty("bypass_timer"));
            test_port_iperf = Integer.parseInt(prop.getProperty("test_port_iperf"));
            test_stunnel_port_iperf = Integer.parseInt(prop.getProperty("test_stunnel_port_iperf"));
            test_port_httping = Integer.parseInt(prop.getProperty("test_port_httping"));
            test_stunnel_port_httping = Integer.parseInt(prop.getProperty("test_stunnel_port_httping"));
            number_of_tirmmrt = Integer.parseInt(prop.getProperty("number_of_tirmmrt"));
            tor_buffer_size = Integer.parseInt(prop.getProperty("tor_buffer_size"));

        } catch (IOException e) {
            e.printStackTrace();
        }
        File file = new File("./configuration/TIR-MMRT_network");
        Scanner sc = new Scanner(file);
        int tirmmrts = 0;
        while (sc.hasNextLine() && tirmmrts < number_of_tirmmrt) {
            tirmmrt_network.add(sc.nextLine());
            tirmmrts++;
        }
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

    private static byte[] bypass(String path) {
        try {
            String my_address = local_host;
            if (bypassAddress.equals(my_address)) {
                return torRequest(path, remote_host, remote_port);
            } else {
                System.err.println("TIR-MMRT connection :" + my_address + " ---> " + bypassAddress);
                return bypassConnection(path);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static byte[] bypassConnection(String path) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        SSLSocketFactory factory =
                (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket =
                (SSLSocket) factory.createSocket(bypassAddress.split(":")[0], Integer.parseInt(stunnel_port));
        socket.startHandshake();
        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        out.write(String.format("GET %s HTTP/1.1", path.trim()).getBytes());

        int n = 0;
        byte[] buffer = new byte[BUF_SIZE];
        while ((n = in.read(buffer, 0, buffer.length)) != -1) {
            //System.out.write(buffer, 0, n);
            baos.write(buffer, 0, n);

        }
        return baos.toByteArray();
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


    private static byte[] torRequest(String path, String remoteAddress, int remotePort) throws IOException {

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        Socket clientSocket = Utilities.socks4aSocketConnection(remoteAddress, remotePort, tor_host, tor_port);

        OutputStream out = clientSocket.getOutputStream();
        out.flush();

        out.write(String.format("GET %s HTTP/1.1\r\n\r\n", path).getBytes());
        out.flush();

        InputStream in = clientSocket.getInputStream();
        int n;
        byte[] buffer = new byte[tor_buffer_size];
        while ((n = in.read(buffer, 0, buffer.length)) >= 0) {
            baos.write(buffer, 0, n);
        }
        clientSocket.close();
        return baos.toByteArray();
    }

}