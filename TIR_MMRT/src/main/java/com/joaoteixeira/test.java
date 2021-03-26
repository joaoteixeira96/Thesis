package com.joaoteixeira;

import org.silvertunnel_ng.netlib.api.NetFactory;
import org.silvertunnel_ng.netlib.api.NetLayerIDs;
import org.silvertunnel_ng.netlib.api.NetSocket;
import org.silvertunnel_ng.netlib.api.util.TcpipNetAddress;
import org.silvertunnel_ng.netlib.util.ByteArrayUtil;
import org.silvertunnel_ng.netlib.util.HttpUtil;

import java.io.IOException;

public class test {
    public static void main(String[] args) throws IOException {
        final String TORCHECK_HOSTNAME = "51.83.75.29";
        final TcpipNetAddress TORCHECK_NETADDRESS = new TcpipNetAddress(TORCHECK_HOSTNAME, 1238);
        // create connection
        final NetSocket topSocket = NetFactory.getInstance().getNetLayerById(NetLayerIDs.TOR_OVER_TLS_OVER_TCPIP)
                .createNetSocket(null, null, TORCHECK_NETADDRESS);
        HttpUtil.getInstance();
        // communicate with the remote side
        final byte[] httpResponse = HttpUtil.get(topSocket, TORCHECK_NETADDRESS, "/", 5000);
        String httpResponseStr = ByteArrayUtil.showAsString(httpResponse);
        System.out.println("http response body: " + httpResponseStr);
        if ("Congratulations. Your browser is configured to use Tor.".contains(httpResponseStr)) {
            System.out.println("works");
        } else {
            System.out.println("something went wrong");
        }
    }
}
