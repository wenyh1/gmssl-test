package com.other.sslengine.peer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.security.SecureRandom;
import java.util.Iterator;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

public class NioSslClient extends NioSslPeer {

    private String remoteAddress;
    private int port;
    private SSLEngine engine;
    private SocketChannel socketChannel;
    private Selector selector;

    public NioSslClient(String protocol, String remoteAddress, int port) throws Exception {
        this.remoteAddress = remoteAddress;
        this.port = port;

        SSLContext context = SSLContext.getInstance(protocol);
        context.init(
                createKeyManagers(serverStore, passwd, passwd),
                createTrustManagers(clientStore, passwd),
                new SecureRandom());

        engine = context.createSSLEngine(remoteAddress, port);
        engine.setUseClientMode(true);

        SSLSession session = engine.getSession();
        myAppData = ByteBuffer.allocate(1024);
        myNetData = ByteBuffer.allocate(session.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(1024);
        peerNetData = ByteBuffer.allocate(session.getPacketBufferSize());
    }

    public boolean connect() throws Exception {
        socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(false);
        socketChannel.connect(new InetSocketAddress(remoteAddress, port));

        while (!socketChannel.finishConnect()) {
            // can do something here...
            System.out.println("连接失败");
        }

        engine.beginHandshake();
        if (doHandshake(socketChannel, engine)) {
            System.out.println("client 握手成功完成！！.HandshakeStatus=" + engine.getHandshakeStatus());
            write("测试下。。");
        }
        return true;
    }

    public void write(String message) throws IOException {
        write(socketChannel, engine, message);
    }

    @Override
    protected void write(SocketChannel socketChannel, SSLEngine engine, String message) throws IOException {
        System.out.println("About to write to the server...");

        myAppData.clear();
        myAppData.put(message.getBytes());
        myAppData.flip();
        while (myAppData.hasRemaining()) {
            myNetData.clear();
            SSLEngineResult result = engine.wrap(myAppData, myNetData);
            switch (result.getStatus()) {
                case OK:
                    myNetData.flip();
                    while (myNetData.hasRemaining()) {
                        socketChannel.write(myNetData);
                    }
                    System.out.println("Message sent to the server: " + message);
                    break;
                case BUFFER_OVERFLOW:
                    myNetData = enlargePacketBuffer(engine, myNetData);
                    break;
                case BUFFER_UNDERFLOW:
                    throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
                case CLOSED:
                    closeConnection(socketChannel, engine);
                    return;
                default:
                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
            }
        }

    }

    public void read() throws Exception {
        read(socketChannel, engine);
    }

    @Override
    protected void read(SocketChannel socketChannel, SSLEngine engine) throws Exception {
        System.out.println("About to read from the server...");

        peerNetData.clear();
        int waitToReadMillis = 50;
        boolean exitReadLoop = false;
        while (!exitReadLoop) {
            int bytesRead = socketChannel.read(peerNetData);
            if (bytesRead > 0) {
                peerNetData.flip();
                while (peerNetData.hasRemaining()) {
                    peerAppData.clear();
                    SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
                    switch (result.getStatus()) {
                        case OK:
                            peerAppData.flip();
                            System.out.println("Server response: " + new String(peerAppData.array()));
                            exitReadLoop = true;
                            break;
                        case BUFFER_OVERFLOW:
                            peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                            break;
                        case BUFFER_UNDERFLOW:
                            peerNetData = handleBufferUnderflow(engine, peerNetData);
                            break;
                        case CLOSED:
                            closeConnection(socketChannel, engine);
                            return;
                        default:
                            throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                    }
                }
            } else if (bytesRead < 0) {
                handleEndOfStream(socketChannel, engine);
                return;
            }
            Thread.sleep(waitToReadMillis);
        }
    }

    public void shutdown() throws IOException {
        System.out.println("About to close connection with the server...");
        closeConnection(socketChannel, engine);
        executor.shutdown();
        System.out.println("Goodbye!");
    }

    public void recive() throws Exception {
        while (true) {
            selector.select();
            Iterator<SelectionKey> selectedKeys = selector.selectedKeys().iterator();
            while (selectedKeys.hasNext()) {
                SelectionKey key = selectedKeys.next();
                SocketChannel sc = ((SocketChannel) key.channel());
                if (key.isConnectable()) {
                    if (sc.isConnectionPending()) {
                        sc.finishConnect();
                    }
                    sc.register(selector, SelectionKey.OP_READ);
                }

                if (key.isReadable()) {
                    read(sc, (SSLEngine) key.attachment());
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        NioSslClient client = new NioSslClient("TLS", "localhost", 1111);
        client.connect();

        //client.shutdown();
    }
}