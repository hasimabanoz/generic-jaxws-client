package com.j32bit.jaxws.client;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;

//This class returns the password for CXF client use
public class MfcPasswordCallbackHandler implements CallbackHandler {

	private String wsPassword;

	public MfcPasswordCallbackHandler() {

	}

	public MfcPasswordCallbackHandler(String password) {
		wsPassword = password;
	}

	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		WSPasswordCallback pc = (WSPasswordCallback) callbacks[0];
		// set WSS password for SOAP message.
		pc.setPassword(wsPassword);
	}

	public void setBirdWsPassword(String wsPassword) {
		this.wsPassword = wsPassword;
		// BirdPasswordCache.setCachedPassword(birdWsPassword);
	}

}
