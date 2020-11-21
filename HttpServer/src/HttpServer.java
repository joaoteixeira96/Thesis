import Utils.Http;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Date;

public class HttpServer {
    public static final int PORT = 1238;
    static final int MAX_BYTES = 102400000;

    public static void main(String[] args) throws IOException {
        ServerSocket ss = new ServerSocket(PORT);
        while (true) {
            try {
                System.out.println("Http server ready at port " + PORT + " waiting for request ...");
                Socket clientSock = ss.accept();
                processClientRequest(clientSock);
                clientSock.close();
            } catch (Exception e) {
                ss.close();
                System.err.println("Http server is going down :(");
                e.printStackTrace();
                System.exit(-1);
            }
        }
    }

    private static void processClientRequest(Socket socket) {
        try {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            String line = Http.readLine(in);
            System.out.println("\nGot: \n\n" + line);
            String[] request = Http.parseHttpRequest(line);
            // ignore, but print the header of the http message
            line = Http.readLine(in);
            while (!line.equals("")) {
                System.out.println(line);
                String[] header = Http.parseHttpHeader(line);
                line = Http.readLine(in);
            }
            System.out.println();
            if (request[0].equalsIgnoreCase("GET") && request[1] != "") {
                sendFile(request[1], out);
            } else {
                sendsNotSupportedPage(out);
            }
        } catch (IOException e) {
            System.err.println(e.getMessage());
        }
    }

    private static void sendsNotSupportedPage(OutputStream out)
            throws IOException {
        String page =
                "<HTML><BODY>HTTP server: request not supported</BODY></HTML>";
        int length = page.length();
        String header = "HTTP/1.0 501 Not Implemented\r\n";
        header += "Date: " + new Date().toString() + "\r\n";
        header += "Content-type: text/html\r\n";
        header += "Server: " + "X-HttpServer" + "\r\n";
        header += "XAlmost-Accept-Ranges: bytes\r\n";
        header += "Content-Length: " + String.valueOf(length) + " \r\n\r\n";
        header += page;
        out.write(header.getBytes());
    }

    /**
     * Sends a simple valid page with the text of the parameter simplePage
     */
    private static void sendsSimplePage(String simplePage, OutputStream out)
            throws IOException {
        String page =
                "<HTML><BODY>HTTP server: " + simplePage + "</BODY></HTML>\r\n";
        int length = page.length();
        String header = "HTTP/1.0 200 OK\r\n";
        header += "Date: " + new Date().toString() + "\r\n";
        header += "Content-type: text/html\r\n";
        header += "Server: " + "X-HttpServer" + "\r\n";
        header += "X-Almost-Accept-Ranges: bytes\r\n";
        header += "Content-Length: " + String.valueOf(length) + " \r\n\r\n";
        header += page;
        out.write(header.getBytes());
    }

    private static void sendFile(String fileName, OutputStream out)
            throws IOException {
        // strips the leading "/"
        String name = fileName.substring(1);
        File f = new File(name);
        System.out.println("I will try to send file: \"" + name + "\"");
        if (name == "") sendsSimplePage("The empty name is not a file", out);
        else if (!f.exists()) sendsSimplePage("File \"" + fileName + "\" does not exist", out);
        else if (!f.isFile()) sendsSimplePage("File \"" + fileName + "\" is not a file", out);
        else if (!f.canRead()) sendsSimplePage("File \"" + fileName + "\" cannot be read", out);
        else {
            // we are going to send something
            long fileSize = f.length();
            long rest = 0;
            rest = fileSize;     // never sends more then available
            if (rest > MAX_BYTES) rest = MAX_BYTES; // never sends more then MAX_BYTES

            // rest is negative or 0 if fileSize < ranges[0] or if ranges[1] < ranges[0]
            // rest is <= still available && <= MAX_BYTES && <= demanded
            long size = rest <= 0 ? 0 : rest; // number of bytes to send

            RandomAccessFile file = new RandomAccessFile(f, "r");
            StringBuilder header = new StringBuilder("");

            if (size == 0 && fileSize > 0) { // || ranges[1] > fileSize-1 ) {
                header.append("HTTP/1.0 416 Range not satisfiable\r\n");
                header.append("Date: " + new Date().toString() + "\r\n");
                header.append("Server: " + "X-HttpServer" + "\r\n");
                header.append("Content-type: " + getContentType(fileName) + "\r\n");
                header.append("Content-Range: bytes *-0\r\n"); //
                file.close();
                out.write(header.toString().getBytes());
                return;
            }
            // send the all file? it covers the case where a range was asked
            // but the all file is sent (bytes=0-fileSize, bytes=0-, bytes=0-something too big)
            else if (size == fileSize) {
                header.append("HTTP/1.0 200 OK\r\n");
                header.append("Date: " + new Date().toString() + "\r\n");
                header.append("Server: " + "X-HttpServer" + "\r\n");
                header.append("Content-type: " + getContentType(fileName) + "\r\n");
                header.append("Content-Length: " + size + " \r\n\r\n");
            } else { // there are ranges and something to send
                header.append("HTTP/1.0 206 Partial Content\r\n");
                header.append("Date: " + new Date().toString() + "\r\n");
                header.append("Server: " + "X-HttpServer" + "\r\n");
                header.append("Content-type: " + getContentType(fileName) + "\r\n");
                header.append("XAlmost-Accept-Ranges: bytes\r\n");
                header.append("Content-Range: bytes " + (size - 1) + "/*\r\n"); // "/"+fileSize+
                header.append("Content-Length: " + size + " \r\n\r\n");
            }
            out.write(header.toString().getBytes());
            // size > 0 since there is something to send
            long bufferSize = (size <= 4096) ? size : 4096;
            byte[] buffer = new byte[(int) bufferSize];
            int totalSent = 0;
            for (; ; ) {
                int n = file.read(buffer, 0, (int) bufferSize);
                if (n == -1) break;
                out.write(buffer, 0, n);
                totalSent += n;
                if (size - totalSent < bufferSize) bufferSize = size - totalSent;
                if (bufferSize == 0) break;
            }
            file.close();
        }
    }

    private static String getContentType(String fileRequested) {
        if (fileRequested.endsWith(".htm") || fileRequested.endsWith(".html"))
            return "text/html";
        else if (fileRequested.endsWith(".jpeg") || fileRequested.endsWith(".png"))
            return "text/jpeg";
        else
            return "text/plain";
    }
}