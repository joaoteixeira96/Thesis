package Utils;

import java.io.IOException;
import java.io.InputStream;


/**
 * Auxiliary methods to deal with HTTP requests and replies
 */
public class Http {

    /**
     * Reads one line from a HTTP header
     */
    public static String readLine(InputStream is) throws IOException {
        StringBuffer sb = new StringBuffer();
        int c;
        while ((c = is.read()) >= 0) {
            if (c == '\r') continue;
            if (c == '\n') break;
            sb.append((char) c);
        }
        return sb.toString();
    }

    /**
     * Parses the first line of the HTTP reply and returns an array
     * of three strings: reply[0] = version, reply[1] = number and reply[2] = result message
     * Example: input "HTTP/1.0 501 Not Implemented"
     * output reply[0] = "HTTP/1.0", reply[1] = "501" and reply[2] = "Not Implemented"
     * <p>
     * If the input is malformed, it returns something unpredictable
     */

    public static String[] parseHttpReply(String reply) {
        String[] result = {"", "", ""};
        int pos0 = reply.indexOf(' ');
        if (pos0 == -1) return result;
        result[0] = reply.substring(0, pos0).trim();
        pos0++;
        int pos1 = reply.indexOf(' ', pos0);
        if (pos1 == -1) return result;
        result[1] = reply.substring(pos0, pos1).trim();
        result[2] = reply.substring(pos1 + 1).trim();
        return result;
    }


    /**
     * Parses an HTTP header returning an array with the name of the attribute header
     * in position 0 and its value in position 1
     * Example, for "Connection: Keep-alive", returns:
     * [0]->"Connection"; [1]->"Keep-alive"
     * <p>
     * If the input is malformed, it returns something unpredictable
     */
    public static String[] parseHttpHeader(String header) {
        String[] result = {"ERROR", ""};
        int pos0 = header.indexOf(':');
        if (pos0 == -1)
            return result;
        result[0] = header.substring(0, pos0).trim();
        result[1] = header.substring(pos0 + 1).trim();
        return result;
    }
}
