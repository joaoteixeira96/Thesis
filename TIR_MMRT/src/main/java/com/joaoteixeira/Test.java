package com.joaoteixeira;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class Test {

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        System.setProperty("javax.net.ssl.trustStore", "./src/main/java/keystore/servers");
        System.setProperty("javax.net.ssl.trustStorePassword", "password");

        String keyPassphrase = "password";

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream("./src/main/java/keystore/server.key"), keyPassphrase.toCharArray());

        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(keyStore, "password".toCharArray())
                .build();

        HttpClient httpClient = HttpClients.custom().setSSLContext(sslContext).build();
        System.out.println(new String(httpClient.execute(new HttpGet("https://localhost:1239/Files/small")).getEntity().getContent().readAllBytes()));
    }

}
