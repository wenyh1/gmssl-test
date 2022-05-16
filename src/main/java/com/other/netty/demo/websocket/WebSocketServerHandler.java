package com.other.netty.demo.websocket;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.*;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.HttpUtil;
import io.netty.util.CharsetUtil;

import java.util.logging.Level;
import java.util.logging.Logger;

public class WebSocketServerHandler extends SimpleChannelInboundHandler<Object> {
	

	private static final Logger logger = Logger.getLogger(WebSocketServerHandler.class.getName());
	
	private WebSocketServerHandshaker handshaker;

	@Override
	protected void messageReceived(ChannelHandlerContext ctx, Object obj)
			throws Exception {
		// 传统的HTTP接入
		if(obj instanceof FullHttpRequest){
			handleHttpRequest(ctx,(FullHttpRequest)obj);
		}
		// WebSocket接入
		else if(obj instanceof WebSocketFrame){
			handleWebSocketFrame(ctx,(WebSocketFrame)obj);
		}
	}
	
	private void handleHttpRequest(ChannelHandlerContext ctx, FullHttpRequest req) throws Exception{
		System.out.println("handleHttpRequest");
		// 如果HTTP解码失败，返回HHTP异常
		if(!req.decoderResult().isSuccess() || (!"websocket".equals(req.headers().get("Upgrade")))){
			sendHttpResponse(ctx,req,new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.BAD_REQUEST));
		}
		
		// 构造握手响应返回，本机测试
		WebSocketServerHandshakerFactory wsFactory = new WebSocketServerHandshakerFactory("ws://localhost:8080/websocket", null, false);
		handshaker =wsFactory.newHandshaker(req);
		if(handshaker==null){
			WebSocketServerHandshakerFactory.sendUnsupportedVersionResponse(ctx.channel());
		}else{
			handshaker.handshake(ctx.channel(), req);
		}
	}
	
	private void handleWebSocketFrame(ChannelHandlerContext ctx, WebSocketFrame frame){
		// 判断是否是关闭链路的指令
		if(frame instanceof CloseWebSocketFrame){
			handshaker.close(ctx.channel(), (CloseWebSocketFrame)frame.retain());
			return;
		}
		
		// 判断是否是Ping消息
		if(frame instanceof PingWebSocketFrame){
			ctx.channel().write(new PongWebSocketFrame(frame.content().retain()));
			return;
		}
		
		// 本例程仅支持文本消息，不支持二进制消息
		if(!(frame instanceof TextWebSocketFrame)){
			 throw new UnsupportedOperationException(String.format("%s frame types not supported", frame.getClass().getName()));
		}
		
		// 返回应答消息
		String request = ((TextWebSocketFrame)frame).text();
		if(logger.isLoggable(Level.FINE)){
			 logger.fine(String.format("%s received %s", ctx.channel(), request));
		}
		
		ctx.channel().write(new TextWebSocketFrame(request+ " , 欢迎使用Netty WebSocket服务，现在时刻："+ new java.util.Date().toString()));
		
		
	}
	
	private static void sendHttpResponse(ChannelHandlerContext ctx, FullHttpRequest req, FullHttpResponse res){
		// 返回应答给客户端
		if(res.status().code() !=200){
			ByteBuf buf = Unpooled.copiedBuffer(res.status().toString(), CharsetUtil.UTF_8);
			res.content().writeBytes(buf);
			buf.release();
			try {
				Http2Headers http2Headers = HttpUtil.toHttp2Headers(res);
				http2Headers.addLong(HttpHeaderNames.CONTENT_LENGTH, res.content().readableBytes());
			}catch (Exception e){
				e.printStackTrace();
			}

		}
		
		// 如果是非Keep-Alive，关闭连接
		ChannelFuture cf = ctx.channel().writeAndFlush(res);

		try {
			Http2Headers http2Headers = HttpUtil.toHttp2Headers(res);
			Boolean keepAlive = Boolean.valueOf(http2Headers.get(HttpHeaderNames.CONTENT_LENGTH).toString());
			if(!keepAlive || res.status().code() != 200){
				cf.addListener(ChannelFutureListener.CLOSE);
			}
		}catch (Exception e){
			e.printStackTrace();
		}
	}
	
	
	@Override
	public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
		ctx.flush();
	}

	@Override
	public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause)
			throws Exception {
		cause.printStackTrace();
		ctx.close();
	}
	
	
	

}
