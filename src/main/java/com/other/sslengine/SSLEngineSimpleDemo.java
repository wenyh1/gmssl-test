package com.other.sslengine;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;

public class SSLEngineSimpleDemo {

    private SSLContext sslc;

    private SSLEngine clientEngine; // client Engine
    private ByteBuffer clientOut; // write side of clientEngine
    private ByteBuffer clientIn; // read side of clientEngine

    private SSLEngine serverEngine; // server Engine
    private ByteBuffer serverOut; // write side of serverEngine
    private ByteBuffer serverIn; // read side of serverEngine

    private ByteBuffer cTOs; // "reliable" transport client->server
    private ByteBuffer sTOc; // "reliable" transport server->client


    private static String serverStore = (System.getProperty("user.dir") + "/src/main/java/com/zhaozhou/netty/demo/ssl/conf/oneway/serverStore.jks");
    private static String clientStore = System.getProperty("user.dir") + "/src/main/java/com/zhaozhou/netty/demo/ssl/conf/oneway/clientStore.jks";
    private static String passwd = "nettyDemo";

    public static void main(String[] args) throws Exception {
        //System.setProperty("javax.net.debug", "ssl");
        SSLEngineSimpleDemo demo = new SSLEngineSimpleDemo();
        demo.runDemo();

        System.out.println("Demo Completed.");
    }

    public SSLEngineSimpleDemo() throws Exception {

        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore ts = KeyStore.getInstance("JKS");

        char[] passphrase = passwd.toCharArray();

        ks.load(new FileInputStream(serverStore), passphrase);
        ts.load(new FileInputStream(clientStore), passphrase);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, passphrase);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ts);

        SSLContext sslCtx = SSLContext.getInstance("TLS");
        sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        sslc = sslCtx;
    }

    private void runDemo() throws Exception {
        boolean dataDone = false;

        createSSLEngines();
        createBuffers();

        SSLEngineResult clientResult; // results from client's last operation
        SSLEngineResult serverResult; // results from server's last operation

        while (!isEngineClosed(clientEngine) || !isEngineClosed(serverEngine)) {
            System.out.println("================");

            clientResult = clientEngine.wrap(clientOut, cTOs);
            System.out.println("client wrap: " + clientResult);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.wrap(serverOut, sTOc);
            System.out.println("server wrap: " + serverResult);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.flip();
            sTOc.flip();

            clientResult = clientEngine.unwrap(sTOc, clientIn);
            System.out.println("client unwrap: " + clientResult);
            runDelegatedTasks(clientResult, clientEngine);

            serverResult = serverEngine.unwrap(cTOs, serverIn);
            System.out.println("server unwrap: " + serverResult);
            runDelegatedTasks(serverResult, serverEngine);

            cTOs.compact();
            sTOc.compact();


            if (!dataDone && (clientOut.limit() == serverIn.position())
                    && (serverOut.limit() == clientIn.position())) {

                /*
                 * A sanity check to ensure we got what was sent.
                 */
                checkTransfer(serverOut, clientIn);
                checkTransfer(clientOut, serverIn);

                System.out.println("\tClosing clientEngine's *OUTBOUND*...");
                clientEngine.closeOutbound();
                // serverEngine.closeOutbound();
                dataDone = true;
            }
        }
    }

    private static void checkTransfer(ByteBuffer a, ByteBuffer b)
            throws Exception {
        a.flip();
        b.flip();

        if (!a.equals(b)) {
            throw new Exception("Data didn't transfer cleanly");
        } else {
            System.out.println("\tData transferred cleanly");
        }

        a.position(a.limit());
        b.position(b.limit());
        a.limit(a.capacity());
        b.limit(b.capacity());
    }

    private static void runDelegatedTasks(SSLEngineResult result,
                                          SSLEngine engine) throws Exception {

        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable runnable;
            while ((runnable = engine.getDelegatedTask()) != null) {
                System.out.println("\trunning delegated task...");
                runnable.run();
            }
            SSLEngineResult.HandshakeStatus hsStatus = engine.getHandshakeStatus();
            if (hsStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                throw new Exception("handshake shouldn't need additional tasks");
            }
            System.out.println("\tnew HandshakeStatus: " + hsStatus);
        }
    }

    private static boolean isEngineClosed(SSLEngine engine) {
        return (engine.isOutboundDone() && engine.isInboundDone());
    }


    private void createSSLEngines() throws Exception {
        /*
         * Configure the serverEngine to act as a server in the SSL/TLS
         * handshake. Also, require SSL client authentication.
         */
        serverEngine = sslc.createSSLEngine("server", 8081);
        serverEngine.setUseClientMode(false);
        serverEngine.setNeedClientAuth(true);

        /*
         * Similar to above, but using client mode instead.
         */
        clientEngine = sslc.createSSLEngine("client", 8080);
        clientEngine.setUseClientMode(true);
    }


    //
    private void createBuffers() {
        SSLSession session = clientEngine.getSession();
        int appBufferMax = session.getApplicationBufferSize();
        int netBufferMax = session.getPacketBufferSize();


        clientIn = ByteBuffer.allocate(appBufferMax + 50);
        serverIn = ByteBuffer.allocate(appBufferMax + 50);

        cTOs = ByteBuffer.allocateDirect(netBufferMax);
        sTOc = ByteBuffer.allocateDirect(netBufferMax);

        clientOut = ByteBuffer.wrap("Hi Server, I'm Client".getBytes());
        serverOut = ByteBuffer.wrap("Hello Client, I'm Server".getBytes());
    }
}
