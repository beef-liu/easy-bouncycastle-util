package com.beef.util.bouncycastle.sign;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.beef.util.bouncycastle.CryptoException;

public class RSASignature extends AbstractSignature {
	public final static String SIGN_ALGORITHM_SHA1_WITH_RSA = "SHA1withRSA";
	
	public final static int KEY_BIT_LEN_1024 = 1024;
	public final static int KEY_BIT_LEN_2048 = 2048;
	

	@Override
	public PrivateKey decodePrivateKey(byte[] encodedKey) throws CryptoException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
			
			return keyFactory.generatePrivate(keySpec);
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
	
	@Override
	public PublicKey decodePublicKey(byte[] encodedKey) throws CryptoException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
			
			return keyFactory.generatePublic(keySpec);
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
	
	
	@Override
	protected KeyPairGenerator createKeyPairGenerator(int keyBitLen) throws CryptoException {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			
			SecureRandom random = createSecureRandom();
			keyGen.initialize(keyBitLen, random);
			
			return keyGen;
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
	
	@Override
	protected SecureRandom createSecureRandom() throws CryptoException {
		try {
			return SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e);
		}
	}
}
