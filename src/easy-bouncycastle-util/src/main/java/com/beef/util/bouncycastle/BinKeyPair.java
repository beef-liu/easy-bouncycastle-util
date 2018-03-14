package com.beef.util.bouncycastle;

public class BinKeyPair {
	private byte[] _privateKey;
	
	private byte[] _publicKey;

	public byte[] getPrivateKey() {
		return _privateKey;
	}

	public void setPrivateKey(byte[] privateKey) {
		_privateKey = privateKey;
	}

	public byte[] getPublicKey() {
		return _publicKey;
	}

	public void setPublicKey(byte[] publicKey) {
		_publicKey = publicKey;
	}
	
	
}
