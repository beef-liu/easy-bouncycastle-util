package com.beef.util.bouncycastle;

public class CryptoException extends Exception {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -8007503022985683014L;

	public CryptoException() {
		super();
	}
	
	public CryptoException(String msg) {
		super(msg);
	}
	
	public CryptoException(Throwable e) {
		super(e);
	}
	
	public CryptoException(String msg, Throwable e) {
		super(msg, e);
	}

}
