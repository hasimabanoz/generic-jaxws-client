package com.j32bit.jaxws.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.FiltersType;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.interceptor.LoggingInInterceptor;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.WSS4JConstants;

public class GenericClient {

	public static void main(String[] args) throws Exception {
		GenericClient genericClient = new GenericClient();
		HelloWorld port = genericClient.createClient("cxf", "cxf");

		System.out.println(port.sayHello("Hasim"));

	}

	public HelloWorld createClient(String wsseUsername, String wssePassword) throws Exception {

		// URL wsdlURL = new URL(targetURI+"?wsdl");
		QName SERVICE_NAME = new QName("http://jaxws.j32bit.com.tr/", "HelloWorld");
		HelloWorldService service = new HelloWorldService(null, SERVICE_NAME);
		HelloWorld port = service.getHelloWorldPort();

		// server'da ssl varsa bu satır açılır
		// setupTLS(port);

		BindingProvider bindingProvider = (BindingProvider) port;
		// TODO endpoint parametrik alınır
		bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, "http://localhost:8080/generic-service/services/hello");

		// Web Service Security SOAP Header
		Map<String, Object> outProps = new HashMap<String, Object>();

		outProps.put(ConfigurationConstants.ACTION, ConfigurationConstants.USERNAME_TOKEN);
		outProps.put(ConfigurationConstants.USER, wsseUsername);
		outProps.put(ConfigurationConstants.PASSWORD_TYPE, WSS4JConstants.PW_TEXT);
		outProps.put(ConfigurationConstants.PW_CALLBACK_REF, new MfcPasswordCallbackHandler(wssePassword));

		// write the actual password to cache
		// BirdPasswordCache.setCachedPassword(wssePassword);

		org.apache.cxf.endpoint.Client client = ClientProxy.getClient(port);

		// Timeouts
		// TODO timeout parametrik alınır
		HTTPConduit http = (HTTPConduit) client.getConduit();
		HTTPClientPolicy httpClientPolicy = new HTTPClientPolicy();
		httpClientPolicy.setConnectionTimeout(10000);
		httpClientPolicy.setReceiveTimeout(10000);
		http.setClient(httpClientPolicy);

		// Handling SoapFaultException for OneWay messages
		// https://issues.apache.org/jira/browse/CXF-5630
		client.getEndpoint().put(org.apache.cxf.message.Message.ROBUST_ONEWAY, true);

		// Server'da Username ve password ile basic auth varsa bu satır açılır
		client.getOutInterceptors().add(new WSS4JOutInterceptor(outProps));

		// Log SOAP request and responses
		LoggingOutInterceptor outLogging = new LoggingOutInterceptor();
		outLogging.setPrettyLogging(true);
		LoggingInInterceptor inLogging = new LoggingInInterceptor();
		inLogging.setPrettyLogging(true);

		// Apply loggers to client
		client.getOutInterceptors().add(outLogging);
		client.getInInterceptors().add(inLogging);
		// client.getInFaultInterceptors().add(inLogging);
		// client.getOutFaultInterceptors().add(outLogging);

		return port;
	}

	private void setupTLS(HelloWorld port) throws FileNotFoundException, IOException, GeneralSecurityException, URISyntaxException {

		HTTPConduit httpConduit = (HTTPConduit) ClientProxy.getClient(port).getConduit();

		TLSClientParameters tlsCP = new TLSClientParameters();

		// NOT: Windows'ta SSLv2Hello hatasi veriyor TLSv1'e cekmek gerekir.
		// tlsCP.setSecureSocketProtocol("SSL");
		tlsCP.setSecureSocketProtocol("TLSv1");
		FiltersType filters = new FiltersType();

		// filters.getInclude().add(".*_EXPORT1024_.*");
		// filters.getInclude().add(".*_EXPORT_.*");
		// filters.getInclude().add(".*_WITH_DES_.*");
		// filters.getInclude().add(".*_128_.*");
		// TODO: Gereksiz chiper setleri silinebilir veya ileride eklenebilir
		filters.getInclude().add("SSL_RSA_WITH_RC4_128_MD5");
		filters.getInclude().add("SSL_RSA_WITH_RC4_128_SHA");
		filters.getInclude().add(".*_128_.*");
		URL resource = GenericClient.class.getClassLoader().getResource("bpm-test.jks");
		File file = new File(resource.toURI());
		tlsCP.setCipherSuitesFilter(filters);
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(file), "aloha32".toCharArray());
		KeyManager[] myKeyManagers = getKeyManagers(keyStore, "aloha32");
		tlsCP.setKeyManagers(myKeyManagers);

		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(new FileInputStream(file), "aloha32".toCharArray());
		TrustManager[] myTrustStoreKeyManagers = getTrustManagers(trustStore);
		tlsCP.setTrustManagers(myTrustStoreKeyManagers);
		httpConduit.setTlsClientParameters(tlsCP);

	}

	private TrustManager[] getTrustManagers(KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException {
		String alg = KeyManagerFactory.getDefaultAlgorithm();
		TrustManagerFactory fac = TrustManagerFactory.getInstance(alg);
		fac.init(trustStore);
		return fac.getTrustManagers();
	}

	private KeyManager[] getKeyManagers(KeyStore keyStore, String keyPassword) throws GeneralSecurityException, IOException {
		String alg = KeyManagerFactory.getDefaultAlgorithm();
		char[] keyPass = keyPassword != null ? keyPassword.toCharArray() : null;
		KeyManagerFactory fac = KeyManagerFactory.getInstance(alg);
		fac.init(keyStore, keyPass);
		return fac.getKeyManagers();
	}

}
