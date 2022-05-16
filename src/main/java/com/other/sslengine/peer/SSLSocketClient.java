package com.other.sslengine.peer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class SSLSocketClient {

    private SSLSocket sslSocket;
    public static void main(String[] args) throws Exception {
        // System.setProperty("javax.net.debug", "ssl");
        SSLSocketClient client = new SSLSocketClient();
        client.init();
        System.out.println("SSLClient initialized.");
        client.process();
    }

    protected String serverStore = (System.getProperty("user.dir") + "/src/main/java/com/zhaozhou/netty/demo/ssl/conf/oneway/serverStore.jks");
    protected String clientStore = System.getProperty("user.dir") + "/src/main/java/com/zhaozhou/netty/demo/ssl/conf/oneway/clientStore.jks";
    protected String passwd = "nettyDemo";

    //客户端将要使用到client.keystore和ca-trust.keystore
    public void init() throws Exception {
        String host = "localhost";
        int port = 1111;
        String protocol = "TLS";

        //初始化SSL上下文
        SSLContext context = SSLContext.getInstance(protocol);
        context.init(
                NioSslPeer.createKeyManagers(serverStore, passwd, passwd),
                NioSslPeer.createTrustManagers(clientStore, passwd),
                new SecureRandom());

        sslSocket = (SSLSocket)context.getSocketFactory().createSocket(host, port);
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
