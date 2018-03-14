package com.beef.util.bouncycastle;

import java.security.KeyPair;
import java.util.List;

public interface ISignature {

	public KeyPair generateKeyPair(int keyBitLen) throws CryptoException;
	public List<KeyPair> generateKeyPairs(int keyBitLen, int count) throws CryptoException;
	
	public BinKeyPair generateEncodedKeyPair(int keyBitLen) throws CryptoException;
	public List<BinKeyPair> generateEncodedKeyPairs(int keyBitLen, int count) throws CryptoException;
	
	public byte[] sign(String signAlgorithm, byte[] encodedKey, 
			byte[] input) throws CryptoException;
	
	public byte[] sign(String signAlgorithm, byte[] encodedKey, 
			byte[] input, int offset, int len) throws CryptoException;
	
	public boolean verifySign(String signAlgorithm, byte[] encodedKey, 
			byte[] input, 
			byte[] signature) throws CryptoException;
	
	public boolean verifySign(String signAlgorithm, byte[] encodedKey, 
			byte[] input, int inputOffset, int inputLen, 
			byte[] signature, int signOffset, int signLen) throws CryptoException;
	
}
