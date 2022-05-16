package com.other.netty.gmssl;

import java.io.FileInputStream;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslHandler;

/**
 * netty+gmssl双向
 */
class Client2 {
    public static String addr = "127.0.0.1";
    public static int port = 3333;

    public static void main(String[] args) throws Exception {
        System.setProperty("javax.net.debug", "ssl");
        EventLoopGroup eventLoopGroup = new NioEventLoopGroup();
        try {
            Bootstrap bootstrap = new Bootstrap();
            bootstrap.group(eventLoopGroup).channel(NioSocketChannel.class).handler(new MyClientInitializer2());
            ChannelFuture channelFuture = bootstrap.connect(addr, port).sync();
            channelFuture.channel().closeFuture().sync();
        } finally {
            eventLoopGroup.shutdownGracefully();
        }
    }
}

class MyClientInitializer2 extends ChannelInitializer<SocketChannel> {
    @Override
    protected void initChannel(SocketChannel ch) throws Exception {
        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jce.provider.GMJCE").newInstance(), 1);
        Security.insertProviderAt((Provider) Class.forName("cn.gmssl.jsse.provider.GMJSSE").newInstance(), 2);
        ChannelPipeline pipeline = ch.pipeline();

        // 加载密钥对
        String pfxfile = "/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/sm2.client.both.pfx";
        String pwdpwd = "12345678";
        KeyStore pfx = KeyStore.getInstance("PKCS12");
        pfx.load(new FileInputStream(pfxfile), pwdpwd.toCharArray());

        // 创建SSLEngine
        SSLContext ctx = createSocketFactory(pfx, pwdpwd.toCharArray(), null);
        SSLEngine sslEngine = ctx.createSSLEngine();
        sslEngine.setUseClientMode(true);
        sslEngine.setEnabledCipherSuites(new String[]{"ECC_SM4_CBC_SM3"});
        sslEngine.setEnabledProtocols("GMSSLv1.1".split(","));

        pipeline.addLast("ssl", new SslHandler(sslEngine));

        pipeline.addLast("framer", new LineBasedFrameDecoder(1024, false, false));
        pipeline.addLast("decoder", new StringDecoder());
        pipeline.addLast("encoder", new StringEncoder());

        /*pipeline.addLast(new HttpClientCodec());
        pipeline.addLast(new HttpObjectAggregator(65536));
        pipeline.addLast(new HttpContentDecompressor());*/
        pipeline.addLast(new ClientHandler2());
    }

    public static SSLContext createSocketFactory(KeyStore kepair, char[] pwd, KeyStore trustStore) throws Exception {
        KeyManager[] kms = null;
        if (kepair != null) {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(kepair, pwd);
            kms = kmf.getKeyManagers();
        }

        TrustManager[] tms = null;
        if (trustStore != null) {
            // 指定指定的证书验证
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(trustStore);
            tms = tmf.getTrustManagers();
        } else {
            // 不验证(信任全部)
            tms = new TrustManager[1];
            tms[0] = new TrustAllManager();
        }

        SSLContext ctx = SSLContext.getInstance("GMSSLv1.1", "GMJSSE");
        java.security.SecureRandom secureRandom = new java.security.SecureRandom();
        ctx.init(kms, tms, secureRandom);
        ctx.getServerSessionContext().setSessionCacheSize(8192);
        ctx.getServerSessionContext().setSessionTimeout(3600);
        return ctx;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}

class ClientHandler2 extends SimpleChannelInboundHandler<String> {
    @Override
    protected void messageReceived(ChannelHandlerContext ctx, String msg) throws Exception {
        System.err.print("recv:" + msg);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        cause.printStackTrace();
        ctx.close();
    }
}