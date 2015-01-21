package com.beef.util.bouncycastle.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.beef.util.bouncycastle.CryptoException;
import com.beef.util.bouncycastle.ICipher;

public class AESCipher implements ICipher {

	@Override
	public byte[] encrypt(byte[] key, byte[] input) throws CryptoException {
		return encrypt(key, input, 0, input.length);
	}
	
	@Override
	public byte[] encrypt(byte[] key, byte[] input, int offset, int len) throws CryptoException {
		checkKeyLen(key);

		try {
			SecretKey secretKey = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			
			cipher.update(input, offset, len);
			return cipher.doFinal();
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public byte[] decrypt(byte[] key, byte[] input) throws CryptoException {
		return decrypt(key, input, 0, input.length);
	}
	
	@Override
	public byte[] decrypt(byte[] key, byte[] input, int offset, int len) throws CryptoException {
		checkKeyLen(key);

		try {
			SecretKey secretKey = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			
			cipher.update(input, offset, len);
			return cipher.doFinal();
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}

	private void checkKeyLen(byte[] key) throws CryptoException {
		if(key.length < 16 || (key.length % 16) != 0) {
			throw new CryptoException("Byte length of key must be (bytelen >= 16) and (bytelen mod 16 = 0)");
		}
	}

	public byte[] encrypt(byte[] key, byte[] iv, byte[] input)
			throws CryptoException {
		return encrypt(key, iv, input, 0, input.length);
	}
	
	@Override
	public byte[] encrypt(byte[] key, byte[] iv, byte[] input, int offset, int len)
			throws CryptoException {
		checkKeyLen(key);

		try {
			SecretKey secretKey = new SecretKeySpec(key, "AES");
			IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParamSpec);
			
			cipher.update(input, offset, len);
			return cipher.doFinal();
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public byte[] decrypt(byte[] key, byte[] iv, byte[] input)
			throws CryptoException {
		return decrypt(key, iv, input, 0, input.length);
	}
	
	@Override
	public byte[] decrypt(byte[] key, byte[] iv, byte[] input, int offset, int len)
			throws CryptoException {
		checkKeyLen(key);

		try {
			SecretKey secretKey = new SecretKeySpec(key, "AES");
			IvParameterSpec ivParamSpec = new IvParameterSpec(iv);
			
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParamSpec);
			
			cipher.update(input, offset, len);
			return cipher.doFinal();
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
}
