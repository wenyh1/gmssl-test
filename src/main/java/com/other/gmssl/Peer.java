package com.other.gmssl;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

// https://github.com/alkarn/sslengine.example/blob/master/src/main/java/alkarn/github/io/sslengine/example/NioSslPeer.java
public abstract class Peer {
    protected final Logger log = Logger.getLogger(Peer.class.getName());

    protected ByteBuffer myAppData; // write时准备的明文数据（未加密）
    protected ByteBuffer myNetData; // myAppData加密后的数据

    protected ByteBuffer peerAppData; // peerNetData解密后的数据
    protected ByteBuffer peerNetData; // read时读取的加密数据

    protected ExecutorService executor = Executors.newSingleThreadExecutor();
    protected String serverStore = (System.getProperty("user.dir") + "/src/main/java/com/zhaozhou/netty/demo/ssl/conf/oneway/serverStore.jks");
    protected String clientStore = System.getProperty("user.dir") + "/src/main/java/com/zhaozhou/netty/demo/ssl/conf/oneway/clientStore.jks";

    protected abstract void read(SocketChannel socketChannel, SSLEngine engine) throws Exception;

    protected abstract void write(SocketChannel socketChannel, SSLEngine engine, String message) throws Exception;


    /**
     * *   <li>1. wrap:     ClientHello</li>
     * *   <li>2. unwrap:   ServerHello/Cert/ServerHelloDone</li>
     * *   <li>3. wrap:     ClientKeyExchange</li>
     * *   <li>4. wrap:     ChangeCipherSpec</li>
     * *   <li>5. wrap:     Finished</li>
     * *   <li>6. unwrap:   ChangeCipherSpec</li>
     * *   <li>7. unwrap:   Finished</li>
     */

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

    protected void closeConnection(SocketChannel socketChannel, SSLEngine engine) throws IOException {
        engine.closeOutbound();
        doHandshake(socketChannel, engine);
        socketChannel.close();
    }

    protected void handleEndOfStream(SocketChannel socketChannel, SSLEngine engine) throws IOException {
        try {
            engine.closeInbound();
        } catch (Exception e) {
            System.out.println("Error：This engine was forced to close inbound, without having received the proper SSL/TLS close notification message from the peer, due to end of stream.");
        }
        closeConnection(socketChannel, engine);
    }

    public static KeyManager[] createKeyManagersJKS() throws Exception {
        String filepath = "/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/sm2.srv1.both.jks";
        String keystorePassword = "12345678";
        KeyStore pfx = KeyStore.getInstance("JKS");
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

    public static KeyManager[] createKeyManagers(String filepath, String keystorePassword) throws Exception {
        // PFX
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

    protected static TrustManager[] createTrustManagers() throws Exception {
        KeyStore trustKeyStore = KeyStore.getInstance("PKCS12");
        trustKeyStore.load(null);
        FileInputStream fin = new FileInputStream("/Users/wd/Documents/Action/project/dble/t6/sm2.oca.pem");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate oca = (X509Certificate) cf.generateCertificate(fin);
        trustKeyStore.setCertificateEntry("oca", oca);
        fin = new FileInputStream("/Users/wd/Documents/Action/project/dble/t6/sm2.rca.pem");
        X509Certificate rca = (X509Certificate) cf.generateCertificate(fin);
        trustKeyStore.setCertificateEntry("rca", rca);

        TrustManagerFactory trustFactory = TrustManagerFactory.getInstance("SunX509");
        trustFactory.init(trustKeyStore);

        TrustManager[] origTms = trustFactory.getTrustManagers();
        List<TrustManager> tms = new ArrayList<TrustManager>();
        boolean verifyServerCert = true;
        for (TrustManager tm : origTms) {
            // wrap X509TrustManager or put original if non-X509 TrustManager
            tms.add(tm instanceof X509TrustManager ? new TrustAllManager((X509TrustManager) tm, verifyServerCert) : tm);
        }
        return tms.toArray(new TrustManager[tms.size()]);
    }
}