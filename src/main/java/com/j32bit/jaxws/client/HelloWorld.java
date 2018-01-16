
package com.j32bit.jaxws.client;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.ws.RequestWrapper;
import javax.xml.ws.ResponseWrapper;

/**
 * This class was generated by the JAX-WS RI. JAX-WS RI 2.2.4-b01 Generated source version: 2.2
 *
 */
@WebService(name = "HelloWorld", targetNamespace = "http://jaxws.j32bit.com.tr/")
@XmlSeeAlso({ ObjectFactory.class })
public interface HelloWorld {

	/**
	 *
	 * @param arg0
	 * @return returns java.lang.String
	 */
	@WebMethod
	@WebResult(targetNamespace = "")
	@RequestWrapper(localName = "sayHello", targetNamespace = "http://jaxws.j32bit.com.tr/", className = "com.j32bit.jaxws.client.SayHello")
	@ResponseWrapper(localName = "sayHelloResponse", targetNamespace = "http://jaxws.j32bit.com.tr/", className = "com.j32bit.jaxws.client.SayHelloResponse")
	public String sayHello(@WebParam(name = "arg0", targetNamespace = "") String arg0);

}