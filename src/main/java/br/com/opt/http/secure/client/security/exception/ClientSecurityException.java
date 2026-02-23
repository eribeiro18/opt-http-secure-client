package br.com.opt.http.secure.client.security.exception;

public class ClientSecurityException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public ClientSecurityException(String msg) {
        super(msg);
    }

	public ClientSecurityException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
