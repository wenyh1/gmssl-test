package com.other.gmssl;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.channels.spi.SelectorProvider;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

public class Server {
    protected final Logger log = Logger.getLogger(Peer.class.getName());

    protected ByteBuffer myAppData; // write时准备的明文数据（未加密）
    protected ByteBuffer myNetData; // myAppData加密后的数据

    protected ByteBuffer peerAppData; // peerNetData解密后的数据
    protected ByteBuffer peerNetData; // read时读取的加密数据

    protected ExecutorService executor = Executors.newSingleThreadExecutor();


    private boolean active;
    private SSLContext context;
    private Selector selector;


    public Server(String protocol, String hostAddress, int port) throws Exception {
        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jce.provider.GMJCE").newInstance(), 1);
        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jsse.provider.GMJSSE").newInstance(), 2);

        context = SSLContext.getInstance("GMSSLv1.1", "GMJSSE");

        //String pfxfile = "/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/ms2.1.server.pfx";
        /*String pfxfile = "/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/ms2.gmssl.server.pfx";
        String pwd = "123";*/


        String pfxfile = "/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/sm2.server0.both.pfx";
        String pwd = "12345678";
        KeyManager[] km = Peer.createKeyManagers(pfxfile, pwd);

        // TrustManager[] tm = createTrustManagers(clientStore, passwd);
        TrustManager[] tm = {new TrustAllManager()};

        context.init(km, tm, new SecureRandom());

        SSLEngine sslEngine = context.createSSLEngine();
        sslEngine.setUseClientMode(false);
        sslEngine.setNeedClientAuth(false); //TODO
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
        Server sslServer = new Server("TLS", "localhost", 22222222);
        sslServer.start();
    }

    protected void closeConnection(SocketChannel socketChannel, SSLEngine engine) throws IOException {
        engine.closeOutbound();
        doHandshake(socketChannel, engine);
        socketChannel.close();
    }

    protected boolean doHandshake(SocketChannel socketChannel, SSLEngine engine) throws IOException {

        System.out.println("About to do handshake...");

        SSLEngineResult result;
        SSLEngineResult.HandshakeStatus handshakeStatus;

        int appBufferSize = engine.getSession().getApplicationBufferSize();
        ByteBuffer myAppData = ByteBuffer.allocate(appBufferSize);
        ByteBuffer peerAppData = ByteBuffer.allocate(appBufferSize);
        myNetData.clear();
        peerNetData.clear();

        handshakeStatus = engine.getHandshakeStatus();
        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED
                && handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            // System.out.println("##doHandshake, status=" + handshakeStatus);
            switch (handshakeStatus) {
                case NEED_UNWRAP: {
                    if (socketChannel.read(peerNetData) < 0) {
                        if (engine.isInboundDone() && engine.isOutboundDone()) {
                            return false;
                        }
                        try {
                            engine.closeInbound();
                        } catch (SSLException e) {
                            System.out.println("Error：This engine was forced to close inbound, without having received the proper SSL/TLS close notification message from the peer, due to end of stream.");
                        }
                        engine.closeOutbound();
                        // After closeOutbound the engine will be set to WRAP state, in order to try to send a close message to the client.
                        handshakeStatus = engine.getHandshakeStatus();
                        break;
                    }
                    peerNetData.flip();
                    try {
                        // result = engine.unwrap(peerNetData, peerAppData);

                        do {
                            result = engine.unwrap(peerNetData, peerAppData);//调用SSLEngine进行unwrap操作
                            // During an handshake renegotiation we might need to perform several unwraps to consume the handshake data.
                        } while (result.getStatus() == SSLEngineResult.Status.OK // 判断状态
                                && result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_UNWRAP
                                && result.bytesProduced() == 0);

                        if (peerAppData.position() == 0 && result.getStatus() == SSLEngineResult.Status.OK && peerNetData.hasRemaining()) {
                            result = engine.unwrap(peerNetData, peerAppData);
                        }
                        peerNetData.compact();
                        handshakeStatus = result.getHandshakeStatus();
                    } catch (SSLException sslException) {
                        System.out.println("Error：A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
                        engine.closeOutbound();
                        handshakeStatus = engine.getHandshakeStatus();
                        break;
                    }
                    switch (result.getStatus()) {
                        case OK:
                            break;
                        case BUFFER_OVERFLOW:
                            // Will occur when peerAppData's capacity is smaller than the data derived from peerNetData's unwrap.
                            peerAppData = enlargeApplicationBuffer(engine, peerAppData);
                            break;
                        case BUFFER_UNDERFLOW:
                            // Will occur either when no data was read from the peer or when the peerNetData buffer was too small to hold all peer's data.
                            peerNetData = handleBufferUnderflow(engine, peerNetData);
                            break;
                        case CLOSED:
                            if (engine.isOutboundDone()) {
                                return false;
                            } else {
                                engine.closeOutbound();
                                handshakeStatus = engine.getHandshakeStatus();
                                break;
                            }
                        default:
                            throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                    }
                    break;
                }
                case NEED_WRAP: {
                    myNetData.clear();
                    try {
                        result = engine.wrap(myAppData, myNetData);
                        handshakeStatus = result.getHandshakeStatus();
                    } catch (SSLException sslException) {
                        System.out.println("Error：A problem was encountered while processing the data that caused the SSLEngine to abort. Will try to properly close connection...");
                        engine.closeOutbound();
                        handshakeStatus = engine.getHandshakeStatus();
                        break;
                    }
                    switch (result.getStatus()) {
                        case OK:
                            myNetData.flip();
                            while (myNetData.hasRemaining()) {
                                socketChannel.write(myNetData);
                            }
                            break;
                        case BUFFER_OVERFLOW:
                            myNetData = enlargePacketBuffer(engine, myNetData);
                            break;
                        case BUFFER_UNDERFLOW:
                            throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
                        case CLOSED:
                            try {
                                myNetData.flip();
                                while (myNetData.hasRemaining()) {
                                    socketChannel.write(myNetData);
                                }
                                // At this point the handshake status will probably be NEED_UNWRAP so we make sure that peerNetData is clear to read.
                                peerNetData.clear();
                            } catch (Exception e) {
                                System.out.println("Error：Failed to send server's CLOSE message due to socket channel's failure.");
                                handshakeStatus = engine.getHandshakeStatus();
                            }
                            break;
                        default:
                            throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
                    }
                    break;
                }
                case NEED_TASK: {
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        executor.execute(task);
                    }
                    handshakeStatus = engine.getHandshakeStatus();
                    break;
                }
                case FINISHED:
                    System.out.println("握手成功！！");
                    break;
                case NOT_HANDSHAKING:
                    System.out.println("不是握手！！");
                    break;
                default:
                    throw new IllegalStateException("Invalid SSL status: " + handshakeStatus);
            }
        }

        return true;

    }


    protected ByteBuffer enlargePacketBuffer(SSLEngine engine, ByteBuffer buffer) {
        return enlargeBuffer(buffer, engine.getSession().getPacketBufferSize());
    }

    protected ByteBuffer enlargeApplicationBuffer(SSLEngine engine, ByteBuffer buffer) {
        return enlargeBuffer(buffer, engine.getSession().getApplicationBufferSize());
    }

    protected ByteBuffer enlargeBuffer(ByteBuffer buffer, int sessionProposedCapacity) {
        if (sessionProposedCapacity > buffer.capacity()) {
            buffer = ByteBuffer.allocate(sessionProposedCapacity);
        } else {
            buffer = ByteBuffer.allocate(buffer.capacity() * 2);
        }
        return buffer;
    }

    protected ByteBuffer handleBufferUnderflow(SSLEngine engine, ByteBuffer buffer) {
        if (engine.getSession().getPacketBufferSize() < buffer.limit()) {
            return buffer;
        } else {
            ByteBuffer replaceBuffer = enlargePacketBuffer(engine, buffer);
            buffer.flip();
            replaceBuffer.put(buffer);
            return replaceBuffer;
        }
    }

    protected void handleEndOfStream(SocketChannel socketChannel, SSLEngine engine) throws IOException {
        try {
            engine.closeInbound();
        } catch (Exception e) {
            System.out.println("Error：This engine was forced to close inbound, without having received the proper SSL/TLS close notification message from the peer, due to end of stream.");
        }
        closeConnection(socketChannel, engine);
    }

    public static KeyManager[] createKeyManagers(String filepath, String keystorePassword) throws Exception {
        KeyStore pfx = KeyStore.getInstance("PKCS12", "GMJSSE");
        InputStream keyStoreIS = new FileInputStream(filepath);
        try {
            pfx.load(new FileInputStream(filepath), keystorePassword.toCharArray());
        } finally {
            if (keyStoreIS != null) {
                keyStoreIS.close();
            }
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(pfx, keystorePassword.toCharArray());
        return kmf.getKeyManagers();
    }

    protected static TrustManager[] createTrustManagers(String filepath, String keystorePassword) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("JKS");
        InputStream trustStoreIS = new FileInputStream(filepath);
        try {
            trustStore.load(trustStoreIS, keystorePassword.toCharArray());
        } finally {
            if (trustStoreIS != null) {
                trustStoreIS.close();
            }
        }
        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);
        return trustFactory.getTrustManagers();
    }
}
