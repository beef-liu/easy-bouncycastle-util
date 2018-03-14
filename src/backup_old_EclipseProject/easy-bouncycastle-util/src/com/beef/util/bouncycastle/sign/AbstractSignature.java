package com.beef.util.bouncycastle.sign;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

import com.beef.util.bouncycastle.BinKeyPair;
import com.beef.util.bouncycastle.CryptoException;
import com.beef.util.bouncycastle.ISignature;

public abstract class AbstractSignature implements ISignature {

	@Override
	public KeyPair generateKeyPair(int keyBitLen) throws CryptoException {
		try {
			KeyPairGenerator keyGen = createKeyPairGenerator(keyBitLen);
			
			return keyGen.generateKeyPair();
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public List<KeyPair> generateKeyPairs(int keyBitLen, int count)
			throws CryptoException {
		try {
			KeyPairGenerator keyGen = createKeyPairGenerator(keyBitLen);

			List<KeyPair> keyPairList = new ArrayList<KeyPair>();
			for(int i = 0; i < count; i++) {
				keyPairList.add(keyGen.generateKeyPair());
			}
			
			return keyPairList;
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public BinKeyPair generateEncodedKeyPair(int keyBitLen)
			throws CryptoException {
		try {
			KeyPair keyPair = generateKeyPair(keyBitLen);
			PrivateKey priKey = keyPair.getPrivate();
			PublicKey pubKey = keyPair.getPublic();
			
			BinKeyPair binKeyPair = new BinKeyPair();
			binKeyPair.setPublicKey(pubKey.getEncoded());
			binKeyPair.setPrivateKey(priKey.getEncoded());
			
			return binKeyPair;
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public List<BinKeyPair> generateEncodedKeyPairs(int keyBitLen, int count)
			throws CryptoException {
		try {
			KeyPairGenerator keyGen = createKeyPairGenerator(keyBitLen);

			List<BinKeyPair> keyPairList = new ArrayList<BinKeyPair>();
			KeyPair keyPair;
			BinKeyPair binKeyPair;
			for(int i = 0; i < count; i++) {
				keyPair = keyGen.generateKeyPair();
				
				binKeyPair = new BinKeyPair();
				binKeyPair.setPublicKey(keyPair.getPublic().getEncoded());
				binKeyPair.setPrivateKey(keyPair.getPrivate().getEncoded());
				
				keyPairList.add(binKeyPair);
			}
			
			return keyPairList;
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public byte[] sign(String signAlgorithm, byte[] encodedKey, 
			byte[] input) throws CryptoException {
		return sign(signAlgorithm, encodedKey, input, 0, input.length);
	}
	
	@Override
	public byte[] sign(String signAlgorithm, byte[] encodedKey, 
			byte[] input, int offset, int len) throws CryptoException {
		try {
			PrivateKey privateKey = decodePrivateKey(encodedKey);

			SecureRandom random = createSecureRandom();
			
			Signature sign = Signature.getInstance(signAlgorithm);
			sign.initSign(privateKey, random);

			sign.update(input, offset, len);
			return sign.sign();
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}

	@Override
	public boolean verifySign(String signAlgorithm, byte[] encodedKey, 
			byte[] input, 
			byte[] signature
			) throws CryptoException {
		return verifySign(signAlgorithm, encodedKey, input, 0, input.length, signature, 0, signature.length);
	}
	
	@Override
	public boolean verifySign(String signAlgorithm, byte[] encodedKey, 
			byte[] input, int inputOffset, int inputLen, 
			byte[] signature, int signOffset, int signLen
			) throws CryptoException {
		try {
			PublicKey publicKey = decodePublicKey(encodedKey);

			Signature sign = Signature.getInstance(signAlgorithm);
			sign.initVerify(publicKey);
			
			sign.update(input, inputOffset, inputLen);
			return sign.verify(signature, signOffset, signLen);
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
	
	public abstract PrivateKey decodePrivateKey(byte[] encodedKey) throws CryptoException;
	
	public abstract PublicKey decodePublicKey(byte[] encodedKey) throws CryptoException;
	
	protected abstract KeyPairGenerator createKeyPairGenerator(int keyBitLen) throws CryptoException;
	
	protected abstract SecureRandom createSecureRandom() throws CryptoException;
	
}
