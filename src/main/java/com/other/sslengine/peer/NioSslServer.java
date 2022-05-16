package com.other.sslengine.peer;

import javax.net.ssl.*;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.security.SecureRandom;
import java.util.Iterator;

public class NioSslServer extends NioSslPeer {
    private boolean active;
    private SSLContext context;
    private Selector selector;


    public NioSslServer(String protocol, String hostAddress, int port) throws Exception {
        context = SSLContext.getInstance(protocol);
        context.init(
                createKeyManagers(serverStore, passwd, passwd),
                createTrustManagers(clientStore, passwd),
                new SecureRandom());

        SSLSession dummySession = context.createSSLEngine().getSession();
        myAppData = ByteBuffer.allocate(dummySession.getApplicationBufferSize());
        myNetData = ByteBuffer.allocate(dummySession.getPacketBufferSize());
        peerAppData = ByteBuffer.allocate(dummySession.getApplicationBufferSize());
        peerNetData = ByteBuffer.allocate(dummySession.getPacketBufferSize());
        dummySession.invalidate();

        selector = SelectorProvider.provider().openSelector();
        ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        serverSocketChannel.socket().bind(new InetSocketAddress(hostAddress, port));
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

    public void stop() {
        System.out.println("Will now close server...");
        active = false;
        executor.shutdown();
        selector.wakeup();
    }

    private void accept(SelectionKey key) throws Exception {
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

    protected void read(SocketChannel socketChannel, SSLEngine engine) throws Exception {
        System.out.println("读取client端发送的data...");

        peerNetData.clear();
        int bytesRead = socketChannel.read(peerNetData);
        if (bytesRead > 0) {
            peerNetData.flip();
            while (peerNetData.hasRemaining()) {
                peerAppData.clear();
                SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
                switch (result.getStatus()) {
                    case OK:
                        peerAppData.flip();
                        System.out.println("Incoming message: " + new String(peerAppData.array()));
                        break;
                    case BUFFER_OVERFLOW:
                        peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                        break;
                    case BUFFER_UNDERFLOW:
                        peerNetData = handleBufferUnderflow(engine, peerNetData);
                        break;
                    case CLOSED:
                        System.out.println("Client wants to close connection...");
                        closeConnection(socketChannel, engine);
                        System.out.println("Goodbye client!");
                        return;
                    default:
                        throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                }
                write(socketChannel, engine, "Hello! I am your server!");
            }
        } else if (bytesRead < 0) {
            System.out.println("Error：Received end of stream. Will try to close connection with client...");
            handleEndOfStream(socketChannel, engine);
            System.out.println("Goodbye client!");
        }
    }

    protected void write(SocketChannel socketChannel, SSLEngine engine, String message) throws Exception {
        System.out.println("About to write to a client...");

        myAppData.clear();
        myAppData.put(message.getBytes());
        myAppData.flip();
        while (myAppData.hasRemaining()) {
            // The loop has a meaning for (outgoing) messages larger than 16KB.
            // Every wrap call will remove 16KB from the original message and send it to the remote peer.
            myNetData.clear();
            SSLEngineResult result = engine.wrap(myAppData, myNetData);
            switch (result.getStatus()) {
                case OK:
                    myNetData.flip();
                    while (myNetData.hasRemaining()) {
                        socketChannel.write(myNetData);
                    }
                    System.out.println("Message sent to the client: " + message);
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

    private boolean isActive() {
        return active;
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "ssl");
        NioSslServer sslServer = new NioSslServer("TLS", "localhost", 1111);
        sslServer.start();
    }
}
