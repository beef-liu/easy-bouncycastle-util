package com.beef.util.bouncycastle.junittest;

import org.junit.Test;

import com.beef.util.bouncycastle.crypto.AESCipher;

public class TestEncryptCipher {

	@Test
	public void testAesWithIV() {
		//key must be 16*n bytes
		String key = "01234567890123450123456789012345";
		//iv must be 16 bytes
		String iv = "0123456789abcdef";
		String input = "Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);";
		
		byte[] keyBytes = key.getBytes();
		byte[] inputBytes = input.getBytes();
		byte[] ivBytes = iv.getBytes();
		
		try {
			AESCipher cipher = new AESCipher();
			byte[] encBytes = cipher.encrypt(keyBytes, ivBytes, inputBytes);
			byte[] decBytes = cipher.decrypt(keyBytes, ivBytes, encBytes);
			
			String decStr = new String(decBytes);
			
			System.out.println("decStr:" + decStr);
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	public void testAes() {
		String key = "01234567890123450123456789012345";
		String input = "Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);";
		
		byte[] keyBytes = key.getBytes();
		byte[] inputBytes = input.getBytes();
		
		try {
			AESCipher cipher = new AESCipher();
			byte[] encBytes = cipher.encrypt(keyBytes, inputBytes);
			byte[] decBytes = cipher.decrypt(keyBytes, encBytes);
			
			String decStr = new String(decBytes);
			
			System.out.println("decStr:" + decStr);
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}

}
