package com.other.netty.demo.ssl.twoway;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;
import io.netty.util.concurrent.GlobalEventExecutor;

import java.net.InetAddress;

public class SslTwoWayServerHandler extends SimpleChannelInboundHandler<String> {
	
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
	protected void messageReceived(ChannelHandlerContext ctx, String msg)
			throws Exception {
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
			throws Exception {
		cause.printStackTrace();
		ctx.close();
	}
	
	

}
