package com.gmssl;


import javax.net.ssl.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

// SSLSocket
public class Client1 {

    private SSLSocket sslSocket;
    private int PORT = 8877;

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "ssl");

        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jce.provider.GMJCE").newInstance(), 1);
        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jsse.provider.GMJSSE").newInstance(), 2);

        Client1 c = new Client1();
        c.init();
        System.out.println("SSLClient initialized.");
        c.process();
    }

    public Client1() {
    }

    public void init() throws Exception {
        SSLContext context = SSLContext.getInstance("GMSSLv1.1", "GMJSSE");

        KeyManager[] km = KeyUtil.KeyManagerUtil.clientKeyManagersPFX();
        TrustManager[] OrgTm = KeyUtil.TrustMangerUtil.clientTrustMangerPFX();
        context.init(km, OrgTm, new SecureRandom());

        /*List<TrustManager> tms = new ArrayList<TrustManager>();
        for (TrustManager tm : OrgTm) {
            tms.add(tm instanceof X509TrustManager ? new TrustAllManager((X509TrustManager) tm, true) : tm);
        }

        if (tms.size() == 0) {
            tms.add(new TrustAllManager());
        }
        context.init(km, tms.toArray(new TrustManager[tms.size()]), new SecureRandom());
        */

        sslSocket = (SSLSocket) context.getSocketFactory().createSocket("localhost", PORT);
        //sslSocket.setEnabledCipherSuites(new String[] {"ECC_SM4_CBC_SM3","ECDHE-SM4-CBC-SM3","ECC-SM4-GCM-SM3","ECDHE-SM4-GCM-SM3"});
        sslSocket.setEnabledCipherSuites(new String[]{"ECC_SM4_CBC_SM3"});
        sslSocket.setTcpNoDelay(true);
        sslSocket.startHandshake();
    }

    public void process() throws Exception {
        String hello = "hello server!";
        OutputStream out = sslSocket.getOutputStream();
        out.write(hello.getBytes(), 0, hello.getBytes().length);
        out.flush();

        InputStream in = sslSocket.getInputStream();
        byte[] buffer = new byte[50];
        in.read(buffer);
        System.out.println(new String(buffer));
    }
}
