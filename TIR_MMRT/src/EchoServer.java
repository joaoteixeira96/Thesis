import java.io.IOException;
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
                    System.out.println("TCP connection " + socket.getInetAddress() + ":" + socket.getPort());
                    executor.execute(() -> {
                        ClassServer cs = new ClassServer(socket);
                        cs.exec();
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
                    System.out.println("UDP: " + packet.getSocketAddress().toString()
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