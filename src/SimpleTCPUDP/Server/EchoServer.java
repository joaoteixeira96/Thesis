package SimpleTCPUDP.Server;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class EchoServer {
    public static final int PORT = 1234;

    public static void main(String[] args) {

        //TODO - create thread for each socket connection with binding port

        // TCP
        new Thread(() -> {
            ExecutorService executor = null;
            try (ServerSocket server = new ServerSocket(PORT)) {
                executor = Executors.newFixedThreadPool(5);
                System.out.println("Listening on TCP port 1234, Say hi!");
                while (true) {
                    final Socket socket = server.accept();
                    executor.execute(() -> {
                        String inputLine = "";
                        try (PrintWriter out = new PrintWriter(
                                socket.getOutputStream(), true);
                             BufferedReader in = new BufferedReader(
                                     new InputStreamReader(socket
                                             .getInputStream()))) {
                            while (!inputLine.equals("!quit")
                                    && (inputLine = in
                                    .readLine()) != null) {
                                System.out.println(socket.toString()
                                        + ": " + inputLine);
                                // Echo server...
                                out.println(inputLine);
                            }
                        } catch (IOException ioe) {
                            ioe.printStackTrace();
                        } finally {
                            try {
                                socket.close();
                            } catch (IOException ioe) {
                                ioe.printStackTrace();
                            }
                        }
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
                byte[] buf = new byte[socket.getReceiveBufferSize()];
                DatagramPacket packet = new DatagramPacket(buf, buf.length);

                System.out.println("Listening on UDP port 1234, Say hi!");
                while (true) {
                    socket.receive(packet);
                    System.out.println(packet.getSocketAddress().toString()
                            + ": " + new String(buf, StandardCharsets.UTF_8));
                    // Echo server
                    socket.send(packet);
                }
            } catch (IOException ioe) {
                System.err.println("Cannot open the port on UDP");
                ioe.printStackTrace();
            } finally {
                System.out.println("Closing UDP server");
            }
        }).start();
    }
}