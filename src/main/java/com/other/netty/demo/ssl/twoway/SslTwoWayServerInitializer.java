package com.other.netty.demo.ssl.twoway;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLEngine;
import java.util.concurrent.TimeUnit;

public class SslTwoWayServerInitializer extends ChannelInitializer<SocketChannel> {

	@Override
	protected void initChannel(SocketChannel sc) throws Exception {
		ChannelPipeline pipeline = sc.pipeline();
		String sChatPath = (System.getProperty("user.dir")+ "/src/main/java/com/zhaozhou/netty/demo/ssl/conf/twoway/serverStore.jks");
		String pwd = "nettyDemo";

		//String sChatPath = "/Users/wd/Documents/Action/project/dble/t2/serverkeystore.jks";
		// String sChatPath = "/Users/wd/Documents/Action/project/dble/t1/SeverS.jks";
		//String pwd = "123456";

		SSLEngine engine = SslTwoWayContextFactory.getServerContext(sChatPath,sChatPath,pwd).createSSLEngine();
		engine.setUseClientMode(false);//设置服务端模式
	    engine.setNeedClientAuth(true);//需要客户端验证
		SslHandler handler = new SslHandler(engine);
		handler.setHandshakeTimeout(5, TimeUnit.MINUTES);
		handler.setCloseNotifyTimeout(5, TimeUnit.MINUTES);
		handler.setHandshakeTimeoutMillis(50000);
		handler.setCloseNotifyTimeoutMillis(50000);
		pipeline.addLast("ssl", new SslHandler(engine));

		// On top of the SSL handler, add the text line codec.
		pipeline.addLast("framer", new LineBasedFrameDecoder(1024, false, false));
		pipeline.addLast("decoder", new StringDecoder());
		pipeline.addLast("encoder", new StringEncoder());

		// and then business logic.
		pipeline.addLast("handler", new SslTwoWayServerHandler());
	}

}
