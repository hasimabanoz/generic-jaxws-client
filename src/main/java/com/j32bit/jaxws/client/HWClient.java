package com.j32bit.jaxws.client;

import java.util.HashMap;
import java.util.Map;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.endpoint.Endpoint;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;

public class HWClient {

	public static void main(String[] args) {
		HelloWorldService service = new HelloWorldService();
		HelloWorld hw = service.getHelloWorldPort();

		Client client = ClientProxy.getClient(hw);
		Endpoint endpoint = client.getEndpoint();

		Map<String, Object> props = new HashMap<String, Object>();
		props.put(WSHandlerConstants.ACTION, WSHandlerConstants.USERNAME_TOKEN);
		props.put(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_TEXT);
		props.put(WSHandlerConstants.PW_CALLBACK_CLASS, UTPasswordCallback.class.getName());
		props.put(WSHandlerConstants.USER, "cxf");

		WSS4JOutInterceptor wssOut = new WSS4JOutInterceptor(props);
		endpoint.getOutInterceptors().add(wssOut);
		System.out.println(hw.sayHello("Sylvestre"));
	}
}
