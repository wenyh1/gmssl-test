package com.gmssl;


import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

// SSLEngine
public class Server extends Peer {

    private SSLContext context;
    private Selector selector;
    private boolean active;
    private int PORT = 8877;

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "ssl");
        Server sslServer = new Server();
        sslServer.start();
    }

    public Server() throws Exception {
        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jce.provider.GMJCE").newInstance(), 1);
        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jsse.provider.GMJSSE").newInstance(), 2);

        context = SSLContext.getInstance("GMSSLv1.1", "GMJSSE");

        KeyManager[] km = KeyUtil.KeyManagerUtil.serverKeyManagersPFX();
        TrustManager[] tm = KeyUtil.TrustMangerUtil.serverTrustMangerPFX(); // empty

        context.init(km, tm, new SecureRandom());

        SSLEngine sslEngine = context.createSSLEngine();
        sslEngine.setUseClientMode(false);
        sslEngine.setNeedClientAuth(true); // TODO 强制的认证客户端证书 感觉没有生效
        sslEngine.setEnabledProtocols("GMSSLv1.1".split(",")); // 服务端使用GMSSL

        SSLSession dummySession = sslEngine.getSession();
        myAppData = ByteBuffer.allocate(dummySession.getApplicationBufferSize());
        myNetData = ByteBuffer.allocate(dummySession.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(dummySession.getApplicationBufferSize());
        peerNetData = ByteBuffer.allocate(dummySession.getPacketBufferSize());
        dummySession.invalidate();

        selector = SelectorProvider.provider().openSelector();
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        serverSocketChannel.socket().bind(new InetSocketAddress("localhost", PORT));
        serverSocketChannel.register(selector, SelectionKey.OP_ACCEPT);
        active = true;
    }

    public void start() throws Exception {
        System.out.println("Initialized and waiting for new connections...");

        while (isActive()) {
            selector.select();
            Iterator<SelectionKey> selectedKeys = selector.selectedKeys().iterator();
            while (selectedKeys.hasNext()) {
                SelectionKey key = selectedKeys.next();
                selectedKeys.remove();
                if (!key.isValid()) {
                    continue;
                }
                if (key.isAcceptable()) {
                    accept(key);
                } else if (key.isReadable()) {
                    read((SocketChannel) key.channel(), (SSLEngine) key.attachment());
                }
            }
        }

        System.out.println("Goodbye!");
    }

    public void accept(SelectionKey key) throws Exception {
        System.out.println("New connection request!");

        SocketChannel socketChannel = ((ServerSocketChannel) key.channel()).accept();
        socketChannel.configureBlocking(false);

        SSLEngine engine = context.createSSLEngine();
        engine.setUseClientMode(false);
        engine.beginHandshake(); // client建立连接后，server才开始握手

        if (doHandshake(socketChannel, engine)) { // 等握手结束后，在进行read的注册
            System.out.println("server 握手成功完成！！.HandshakeStatus=" + engine.getHandshakeStatus());
            socketChannel.register(selector, SelectionKey.OP_READ, engine);
        } else {
            socketChannel.close();
            System.out.println("Connection closed due to handshake failure.");
        }
    }

    private boolean isActive() {
        return active;
    }

    public void stop() {
        System.out.println("Will now close server...");
        active = false;
        executor.shutdown();
        selector.wakeup();
    }

}
