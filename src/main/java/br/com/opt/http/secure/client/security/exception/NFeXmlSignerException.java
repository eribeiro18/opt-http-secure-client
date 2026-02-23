package br.com.opt.http.secure.client.security.exception;

public class NFeXmlSignerException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public NFeXmlSignerException(String msg) {
        super(msg);
    }

	public NFeXmlSignerException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
