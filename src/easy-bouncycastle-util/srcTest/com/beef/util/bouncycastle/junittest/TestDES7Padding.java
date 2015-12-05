package com.beef.util.bouncycastle.junittest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import com.beef.util.bouncycastle.CryptoException;
import com.beef.util.bouncycastle.util.BouncyCastle;

public class TestDES7Padding {
	
	@Test
	public void test1() {
		try {
			String key = "12345678";
			String input = "test001";
			
			byte[] enc = encrypt(key.getBytes(), input.getBytes());
			byte[] dec = decrypt(key.getBytes(), enc);
			
			String input2 = new String(dec);
			
			System.out.println("input2:" + input2);
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	public byte[] encrypt(byte[] key, byte[] input) throws CryptoException {
		return encrypt(key, input, 0, input.length);
	}
	
	public byte[] encrypt(byte[] key, byte[] input, int offset, int len) throws CryptoException {
		try {
			SecretKey secretKey = new SecretKeySpec(key, "DES");
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS7Padding", BouncyCastle.Provider);
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			
			return cipher.doFinal(input, offset, len);
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
	
	public byte[] decrypt(byte[] key, byte[] input) throws CryptoException {
		return decrypt(key, input, 0, input.length);
	}
	
	public byte[] decrypt(byte[] key, byte[] input, int offset, int len) throws CryptoException {
		try {
			SecretKey secretKey = new SecretKeySpec(key, "DES");
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS7Padding", BouncyCastle.Provider);
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			
			return cipher.doFinal(input, offset, len);
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}

}
