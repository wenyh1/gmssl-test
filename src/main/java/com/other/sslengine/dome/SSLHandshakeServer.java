package com.other.sslengine.dome;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.util.Iterator;
import java.util.logging.Logger;

public class SSLHandshakeServer {
    private static Logger logger = Logger.getLogger(SSLHandshakeServer.class.getName());

    private SocketChannel sc; //channel
    private Selector selector; //NIO通道

    private SSLEngine sslEngine; //SSLEngine引擎

    private SSLEngineResult.HandshakeStatus hsStatus;
    private SSLEngineResult.Status status;

    private ByteBuffer myNetData;
    private ByteBuffer myAppData;
    private ByteBuffer peerNetData;
    private ByteBuffer peerAppData;//四个buffer缓冲区

    private ByteBuffer dummy = ByteBuffer.allocate(0);

    private static String serverStore = (System.getProperty("user.dir") + "/src/main/java/com/zhaozhou/netty/demo/ssl/conf/oneway/serverStore.jks");

    public void run() throws Exception {
        char[] password = "nettyDemo".toCharArray();
        KeyStore trustStore = KeyStore.getInstance("JKS");
        InputStream in = this.getClass().getResourceAsStream(serverStore);
        trustStore.load(in, password);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(trustStore, password);

        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(kmf.getKeyManagers(), null, null);

        sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(false);

        SSLSession session = sslEngine.getSession(); // 初始化SSLEngine

        myAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(session.getApplicationBufferSize());
        peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerNetData.clear();//定义四个缓冲区

        //NIO的流程
        ServerSocketChannel serverChannel = ServerSocketChannel.open();
        serverChannel.configureBlocking(false);
        selector = Selector.open();
        ServerSocket serverSocket = serverChannel.socket();

        serverSocket.bind(new InetSocketAddress(443));
        serverChannel.register(selector, SelectionKey.OP_ACCEPT);
        logger.info("Server listens on port 443... ...");
        while (true) {
            selector.select();
            Iterator<SelectionKey> it = selector.selectedKeys().iterator();
            while (it.hasNext()) {
                SelectionKey selectionKey = it.next();
                it.remove();
                handleRequest(selectionKey); //当SelectionKey有事件进来后，进行NIO的处理
            }
        }
    }

    private void handleRequest(SelectionKey key) throws Exception {
        if (key.isAcceptable()) {
            ServerSocketChannel ssc = (ServerSocketChannel) key.channel();
            SocketChannel channel = ssc.accept();
            channel.configureBlocking(false);
            channel.register(selector, SelectionKey.OP_READ);//当rigister事件发生后，下一步就是读了
        } else if (key.isReadable()) {
            sc = (SocketChannel) key.channel();
            logger.info("Server handshake begins... ...");
            //从这里，SSL的交互就开始了
            sslEngine.beginHandshake(); // 开始begin握手
            hsStatus = sslEngine.getHandshakeStatus();
            doHandshake();
            if (hsStatus == SSLEngineResult.HandshakeStatus.FINISHED) {//当握手阶段告一段落，握手完毕
                key.cancel();
                sc.close();
            }
            logger.info("Server handshake completes... ...");
        }
    }

    private void doHandshake() throws IOException {
        SSLEngineResult result;
        while (hsStatus != SSLEngineResult.HandshakeStatus.FINISHED
                && hsStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {//一个大的while循环
            logger.info("handshake status: " + hsStatus);
            switch (hsStatus) {
                case NEED_TASK:// 指定delegate任务
                    Runnable runnable;
                    while ((runnable = sslEngine.getDelegatedTask()) != null) {
                        runnable.run(); // 因为耗时比较长，所以需要另起一个线程
                    }
                    hsStatus = sslEngine.getHandshakeStatus();
                    break;
                case NEED_UNWRAP:// 需要进行入站了，说明socket缓冲区中有数据包进来了
                    int count = sc.read(peerNetData);//从socket中进行读取
                    if (count <= 0) {
                        logger.info("no data is read for unwrap.");
                        break;
                    }
                    logger.info("data count: " + count);
                    logger.info("data read: " + new String(peerNetData.array()));
                    peerNetData.flip();
                    peerAppData.clear();
                    do {
                        result = sslEngine.unwrap(peerNetData, peerAppData);//调用SSLEngine进行unwrap操作
                        logger.info("Unwrapping:\n" + result);
                        // During an handshake renegotiation we might need to perform several unwraps to consume the handshake data.
                    } while (result.getStatus() == SSLEngineResult.Status.OK // 判断状态
                            && result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP
                            && result.bytesProduced() == 0);

                    if (peerAppData.position() == 0
                            && result.getStatus() == SSLEngineResult.Status.OK
                            && peerNetData.hasRemaining()) {
                        result = sslEngine.unwrap(peerNetData, peerAppData);
                        logger.info("Unwrapping:\n" + result);
                    }

                    hsStatus = result.getHandshakeStatus();
                    status = result.getStatus();
                    assert status != status.BUFFER_OVERFLOW : "buffer not overflow." + status.toString();

                    peerNetData.compact(); // Prepare the buffer to be written again.
                    peerAppData.flip(); // And the app buffer to be read.

                    break;
                case NEED_WRAP:// 需要出栈
                    myNetData.clear();
                    result = sslEngine.wrap(dummy, myNetData); // 意味着从应用程序中发送数据到socket缓冲区中，先wrap
                    hsStatus = result.getHandshakeStatus();
                    status = result.getStatus();
                    while (status != SSLEngineResult.Status.OK) {
                        logger.info("status: " + status);
                        switch (status) {
                            case BUFFER_OVERFLOW:
                                break;
                            case BUFFER_UNDERFLOW:
                                break;
                        }
                    }
                    myNetData.flip();
                    sc.write(myNetData); //最后再发送socketchannel
                    break;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        new SSLHandshakeServer().run();
    }
}
