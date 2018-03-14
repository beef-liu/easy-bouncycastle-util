package com.beef.util.bouncycastle;

public interface ICipher {
	
	public byte[] encrypt(byte[] key, byte[] input) throws CryptoException;
	public byte[] decrypt(byte[] key, byte[] input) throws CryptoException;
	
	public byte[] encrypt(byte[] key, byte[] input, int offset, int len) throws CryptoException;
	public byte[] decrypt(byte[] key, byte[] input, int offset, int len) throws CryptoException;
	
	public byte[] encrypt(byte[] key, byte[] iv, byte[] input) throws CryptoException;
	public byte[] decrypt(byte[] key, byte[] iv, byte[] input) throws CryptoException;
	
	public byte[] encrypt(byte[] key, byte[] iv, byte[] input, int offset, int len) throws CryptoException;
	public byte[] decrypt(byte[] key, byte[] iv, byte[] input, int offset, int len) throws CryptoException;
}
