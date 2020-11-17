package Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/*
 * Utils.ClassServer.java -- a simple file server that can serve
 * Http get request in both clear and secure channel
 */

public class FileManager {


    public static byte[] retrieveFile(String path) throws IOException {


        File file = new File(path);
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