package com.beef.util.bouncycastle.util;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class DigestUtil {
	static {
		BouncyCastle.initProvider();
	};
	
	public static byte[] ripemd160(byte[] input) throws NoSuchAlgorithmException, NoSuchProviderException {
		return ripemd160(input, 0, input.length);
	}
	
	public static byte[] ripemd160(byte[] input, int offset, int len) throws NoSuchAlgorithmException, NoSuchProviderException {
		return digest("RIPEMD160", "BC", input, offset, len);
	}

	public static int ripemd160( 
			byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset, int outputLen) throws NoSuchAlgorithmException, DigestException, NoSuchProviderException {
		return digest("RIPEMD160", "BC", input, inputOffset, inputLen, output, outputOffset, outputLen);
	}
	
	public static byte[] md5(byte[] input) throws NoSuchAlgorithmException {
		return md5(input, 0, input.length);
	}
	
	public static byte[] md5(byte[] input, int offset, int len) throws NoSuchAlgorithmException {
		return digest("MD5", input, offset, len);
	}

	public static int md5( 
			byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset, int outputLen) throws NoSuchAlgorithmException, DigestException {
		return digest("MD5", input, inputOffset, inputLen, output, outputOffset, outputLen);
	}
	
	public static byte[] sha1(byte[] input) throws NoSuchAlgorithmException {
		return sha1(input, 0, input.length);
	}
	
	public static byte[] sha1(byte[] input, int offset, int len) throws NoSuchAlgorithmException {
		return digest("SHA-1", input, offset, len);
	}

	public static int sha1( 
			byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset, int outputLen) throws NoSuchAlgorithmException, DigestException {
		return digest("SHA-1", input, inputOffset, inputLen, output, outputOffset, outputLen);
	}

	public static byte[] sha256(byte[] input) throws NoSuchAlgorithmException {
		return sha256(input, 0, input.length);
	}
	
	public static byte[] sha256(byte[] input, int offset, int len) throws NoSuchAlgorithmException {
		return digest("SHA-256", input, offset, len);
	}

	public static int sha256( 
			byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset, int outputLen) throws NoSuchAlgorithmException, DigestException {
		return digest("SHA-256", input, inputOffset, inputLen, output, outputOffset, outputLen);
	}
	
	public static byte[] sha384(byte[] input) throws NoSuchAlgorithmException {
		return sha384(input, 0, input.length);
	}
	
	public static byte[] sha384(byte[] input, int offset, int len) throws NoSuchAlgorithmException {
		return digest("SHA-384", input, offset, len);
	}

	public static int sha384( 
			byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset, int outputLen) throws NoSuchAlgorithmException, DigestException {
		return digest("SHA-384", input, inputOffset, inputLen, output, outputOffset, outputLen);
	}
	
	public static byte[] sha512(byte[] input) throws NoSuchAlgorithmException {
		return sha512(input, 0, input.length);
	}

	public static byte[] sha512(byte[] input, int offset, int len) throws NoSuchAlgorithmException {
		return digest("SHA-512", input, offset, len);
	}

	public static int sha512( 
			byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset, int outputLen) throws NoSuchAlgorithmException, DigestException {
		return digest("SHA-512", input, inputOffset, inputLen, output, outputOffset, outputLen);
	}

	public static byte[] digest(String algorithm, byte[] input, int offset, int len) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		
		md.update(input, offset, len);
		return md.digest();
	}
	
	public static byte[] digest(String algorithm, String provider, byte[] input, int offset, int len) throws NoSuchAlgorithmException, NoSuchProviderException {
		MessageDigest md = MessageDigest.getInstance(algorithm, provider);
		
		md.update(input, offset, len);
		return md.digest();
	}

	public static int digest(String algorithm, 
			byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset, int outputLen) throws NoSuchAlgorithmException, DigestException {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		
		md.update(input, inputOffset, inputLen);
		return md.digest(output, outputOffset, outputLen);
	}
	
	public static int digest(String algorithm, String provider, 
			byte[] input, int inputOffset, int inputLen,
			byte[] output, int outputOffset, int outputLen) throws NoSuchAlgorithmException, NoSuchProviderException, DigestException {
		MessageDigest md = MessageDigest.getInstance(algorithm, provider);
		
		md.update(input, inputOffset, inputLen);
		return md.digest(output, outputOffset, outputLen);
	}
	
}
