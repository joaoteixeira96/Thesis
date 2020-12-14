package Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.StringTokenizer;

/*
 * Utils.ClassServer.java -- a simple file server.key that can serve
 * Http get request in both clear and secure channel
 */

public class FileReader {


    public static byte[] retrieveFile(String path) throws IOException {
        StringTokenizer parse = new StringTokenizer(path);
        String method = parse.nextToken().toUpperCase(); // we get the HTTP method of the client
        String fileRequested = parse.nextToken();// we get file requested

        File file = new File(fileRequested);
        int fileLength = (int) file.length();

        byte[] fileData = readFileData(file, fileLength);
        return fileData;
    }

    private static byte[] readFileData(File file, int fileLength) throws IOException {
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


}