package com.other.gmssl;

import com.gmssl.KeyUtil;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

public class SocketClient {

    private SSLSocket sslSocket;

    public static void main(String[] args) throws Exception {

        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jce.provider.GMJCE").newInstance(), 1);
        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jsse.provider.GMJSSE").newInstance(), 2);

        System.setProperty("javax.net.debug", "ssl");
        SocketClient client = new SocketClient();
        client.init();
        System.out.println("SSLClient initialized.");
        client.process();
    }

    //客户端将要使用到client.keystore和ca-trust.keystore
    public void init() throws Exception {
        String host = "localhost";
        int port = 8877;

        //初始化SSL上下文
        SSLContext context = SSLContext.getInstance("GMSSLv1.1", "GMJSSE");
        //String pfxfile = "/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/test.pfx";
        String pfxfile = "/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/ms2.gmssl.server.pfx";
        String pwd = "123";
        //String pfxfile = "/Users/wd/Documents/Action/project/gmssl/GM.Example/keystore/sm2.user1.both.pfx";
        //String pfxfile = "/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/sm2.client.both.pfx";
        //String pwd = "12345678";
        KeyManager[] km = Peer.createKeyManagers(pfxfile, pwd);

        // TrustManager[] tm = {new TrustAllManager()};
        TrustManager[] tm = KeyUtil.TrustMangerUtil.clientTrustMangerPFX();

        context.init(km, tm, new SecureRandom());
        sslSocket = (SSLSocket) context.getSocketFactory().createSocket(host, port);
        //sslSocket.setEnabledCipherSuites(new String[] {"ECC_SM4_CBC_SM3","ECDHE-SM4-CBC-SM3","ECC-SM4-GCM-SM3","ECDHE-SM4-GCM-SM3"});
        sslSocket.setEnabledCipherSuites(new String[]{"ECC_SM4_CBC_SM3"});
        sslSocket.setTcpNoDelay(true); // TODO 需要了解下作用
        sslSocket.startHandshake();
    }

    public void process() throws Exception {
        //往SSLSocket中写入数据
        String hello = "hello boy!";
        OutputStream out = sslSocket.getOutputStream();
        out.write(hello.getBytes(), 0, hello.getBytes().length);
        out.flush();

        //从SSLSocket中读取数据
        InputStream in = sslSocket.getInputStream();
        byte[] buffer = new byte[50];
        in.read(buffer);
        System.out.println(new String(buffer));
    }
}
