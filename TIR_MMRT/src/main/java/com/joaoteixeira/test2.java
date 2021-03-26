package com.joaoteixeira;

import com.msopentech.thali.java.toronionproxy.Utilities;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class test2 {
    public static void main(String[] args) throws IOException {

        // Start a hidden service listener
        int hiddenServicePort = 1238;
        int localPort = 9050;
        String OnionAddress = "51.83.75.29";

        Socket clientSocket = Utilities.socks4aSocketConnection(OnionAddress, hiddenServicePort, "127.0.0.1", localPort);

        OutputStream out = clientSocket.getOutputStream();
        out.flush();

        out.write("GET /Files/small HTTP1.1\r\n\r\n".getBytes());
        out.flush();

        InputStream in = clientSocket.getInputStream();
        byte[] buffer = new byte[536];
        while ((in.read(buffer, 0, buffer.length)) != -1) {
            System.err.println(new String(buffer));
        }
        clientSocket.close();
    }
}