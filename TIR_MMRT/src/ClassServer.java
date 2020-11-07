import java.io.*;
import java.net.Socket;
import java.util.Date;
import java.util.StringTokenizer;

/*
 * ClassServer.java -- a simple file server that can serve
 * Http get request in both clear and secure channel
 */

public class ClassServer {

    private Socket socket = null;

    /**
     * Constructs a ClassServer based on <b>ss</b> and
     * obtains a file's bytecodes using the method <b>getBytes</b>.
     */
    protected ClassServer(Socket s) {
        socket = s;
    }

    protected ClassServer() {
    }

    /**
     * The "listen" thread that accepts a connection to the
     * server, parses the header to obtain the file name
     * and sends back the bytes for the file (or error
     * if the file is not found or the response was malformed).
     */
    public void execTCP() {
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
                    String input = in.readLine();
                    StringTokenizer parse = new StringTokenizer(input);
                    String method = parse.nextToken().toUpperCase(); // we get the HTTP method of the client
                    // we get file requested
                    String fileRequested = parse.nextToken();

                    System.out.println("File request path: " + fileRequested + " from " + socket.getInetAddress() + ":" + socket.getPort());

                    File file = new File(fileRequested);
                    int fileLength = (int) file.length();
                    String content = getContentType(fileRequested);

                    byte[] fileData = readFileData(file, fileLength);

                    // send HTTP Headers
                    out.println("HTTP/1.1 200 OK");
                    out.println("Date: " + new Date());
                    out.println("Content-type: " + content);
                    out.println("Content-length: " + fileLength);
                    out.println(); // blank line between headers and content, very important !
                    rawOut.write(fileData, 0, fileLength);
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

    public byte[] execUDP(String path) throws IOException {
        StringTokenizer parse = new StringTokenizer(path);
        String method = parse.nextToken().toUpperCase(); // we get the HTTP method of the client
        // we get file requested
        String fileRequested = parse.nextToken();

        File file = new File(fileRequested);
        int fileLength = (int) file.length();

        byte[] fileData = readFileData(file, fileLength);
        return fileData;
    }

    private byte[] readFileData(File file, int fileLength) throws IOException {
        FileInputStream fileIn = null;
        byte[] fileData = new byte[fileLength];

        try {
            fileIn = new FileInputStream(file);
            fileIn.read(fileData);
        } finally {
            if (fileIn != null)
                fileIn.close();
        }

        return fileData;
    }

    private String getContentType(String fileRequested) {
        if (fileRequested.endsWith(".htm") || fileRequested.endsWith(".html"))
            return "text/html";
        else
            return "text/plain";
    }
}