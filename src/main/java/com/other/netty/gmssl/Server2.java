package com.other.netty.gmssl;

import java.io.*;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.*;
import javax.net.ssl.*;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslHandler;

import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import io.netty.util.concurrent.GlobalEventExecutor;

/**
 * netty+gmssl双向
 */
public class Server2
{
	public Server2()
	{
	}

	public static void main(String[] args) throws Exception
	{
		System.setProperty("javax.net.debug", "ssl");
		Security.insertProviderAt((Provider)Class.forName("cn.gmssl.jce.provider.GMJCE").newInstance(), 1);
		Security.insertProviderAt((Provider)Class.forName("cn.gmssl.jsse.provider.GMJSSE").newInstance(), 2);
		
		int port = 3333;
		EventLoopGroup bossGroup = new NioEventLoopGroup();
		EventLoopGroup wokerGroup = new NioEventLoopGroup();
		try
		{
			ServerBootstrap serverBootstrap = new ServerBootstrap();
			serverBootstrap.group(bossGroup, wokerGroup).channel(NioServerSocketChannel.class).childHandler(new MyServerInitializer2());
			ChannelFuture channelFuture = serverBootstrap.bind(port).sync();
			System.out.println("服务已开启: 监听"+port+"...");
			channelFuture.channel().closeFuture().sync();
		}
		finally
		{
			bossGroup.shutdownGracefully();
			wokerGroup.shutdownGracefully();
		}
	}
}

class MyServerInitializer2 extends ChannelInitializer<SocketChannel>
{
	@Override
	protected void initChannel(SocketChannel ch) throws Exception
	{
		ChannelPipeline pipeline = ch.pipeline();
		
		// 加载密钥对
		// String pfxfile = "/Volumes/Keyaas/Projects/GM.Test2/src/netty/sm2.srv1.both.pfx";
		String pfxfile = "/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/sm2.server0.both.pfx";
		String pwdpwd = "12345678";
		KeyStore pfx = KeyStore.getInstance("PKCS12");
		pfx.load(new FileInputStream(pfxfile), pwdpwd.toCharArray());
		
		// 加载CA链
    	KeyStore trustStore = KeyStore.getInstance("PKCS12");
    	trustStore.load(null);
        FileInputStream fin = new FileInputStream("/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/sm2.oca.pem");
    	CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate oca = (X509Certificate)cf.generateCertificate(fin);
        trustStore.setCertificateEntry("oca", oca);
        fin = new FileInputStream("/Users/wd/Documents/Action/project/gmssl/netty-demo-master/src/main/java/com/zhaozhou/gmssl/keystore/sm2.rca.pem");
        X509Certificate rca = (X509Certificate)cf.generateCertificate(fin);
        trustStore.setCertificateEntry("rca", rca);

        // 创建SSLEngine
    	SSLContext ctx = createServerSocketFactory(pfx, pwdpwd.toCharArray(), trustStore);
		SSLEngine sslEngine = ctx.createSSLEngine();
		sslEngine.setUseClientMode(false);
		sslEngine.setNeedClientAuth(true);
		sslEngine.setWantClientAuth(true);
		sslEngine.setEnabledProtocols("GMSSLv1.1".split(","));
		
		pipeline.addFirst("ssl", new SslHandler(sslEngine));
		
//		pipeline.addLast(new HttpResponseEncoder());
//		pipeline.addLast(new HttpRequestDecoder());
//		pipeline.addLast(new HttpServerInboundHandler2());

		// On top of the SSL handler, add the text line codec.
		pipeline.addLast("framer", new LineBasedFrameDecoder(1024, false, false));
		pipeline.addLast("decoder", new StringDecoder());
		pipeline.addLast("encoder", new StringEncoder());


		pipeline.addLast("handler", new HttpServerInboundHandler2());
	}

	public static SSLContext createServerSocketFactory(KeyStore kepair, char[] pwd, KeyStore trustStore) throws Exception
	{
		KeyManager[] kms = null;
		if (kepair != null)
		{
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			kmf.init(kepair, pwd);
			kms = kmf.getKeyManagers();
		}
		
		TrustManager[] tms = null;
		if(trustStore != null)
		{
			// 指定指定的证书验证
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init(trustStore);
			tms = tmf.getTrustManagers();
		}
		else
		{
			// 不验证(信任全部)
			tms = new TrustManager[1];
			tms[0] = new TrustAllManager();
		}

		SSLContext ctx = SSLContext.getInstance(cn.gmssl.jsse.provider.GMJSSE.GMSSLv11, cn.gmssl.jsse.provider.GMJSSE.NAME);
		SecureRandom secureRandom = new SecureRandom();
		ctx.init(kms, tms, secureRandom);
		ctx.getServerSessionContext().setSessionCacheSize(8192);
		ctx.getServerSessionContext().setSessionTimeout(3600);
		return ctx;
	}

	@Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) 
    {
    	cause.printStackTrace();
        ctx.close();
    }
}

class HttpServerInboundHandler2 extends SimpleChannelInboundHandler<String>
{
	static final ChannelGroup channels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);

	@Override
	public void channelActive(final ChannelHandlerContext ctx) throws Exception {
		// Once session is secured, send a greeting and register the channel to
		// the global channel
		// list so the channel received the messages from others.
		ctx.pipeline().get(SslHandler.class).handshakeFuture()
				.addListener(new GenericFutureListener<Future<Channel>>() {

					@Override
					public void operationComplete(Future<Channel> arg0)
							throws Exception {
						ctx.writeAndFlush("Welcome to "+ InetAddress.getLocalHost().getHostName()+ " secure chat service!\n");
						ctx.writeAndFlush("Your session is protected by "+ ctx.pipeline().get(SslHandler.class).engine().getSession().getCipherSuite()+ " cipher suite.\n");
						channels.add(ctx.channel());
					}
				});
	}

	@Override
	protected void messageReceived(ChannelHandlerContext ctx, String msg) throws Exception {
		// Send the received message to all channels but the current one.
		System.out.print("recv from " + "[" + ctx.channel().remoteAddress() + "]，msg=" + msg);
		for (Channel c : channels) {
			if (c != ctx.channel()) {
				c.writeAndFlush("[" + ctx.channel().remoteAddress() + "] "+ msg);
			} else {
				c.writeAndFlush("[you] " + msg);
			}
		}

		// Close the connection if the client has sent 'bye'.
		if ("bye".equals(msg.toLowerCase())) {
			ctx.close();
		}
	}


    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) 
    {
		cause.printStackTrace();
		ctx.close();
    }
}