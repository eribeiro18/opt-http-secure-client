package br.com.opt.http.secure.client.security.exception;

public class XmlJaxbHandlerException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public XmlJaxbHandlerException(String msg) {
        super(msg);
    }
	
	public XmlJaxbHandlerException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
