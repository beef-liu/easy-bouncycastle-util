package com.beef.util.bouncycastle.sign;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import com.beef.util.bouncycastle.BinKeyPair;
import com.beef.util.bouncycastle.CryptoException;
import com.beef.util.bouncycastle.ISignature;
import com.beef.util.bouncycastle.util.BouncyCastle;

public class ECDSAPrimeCipher implements ISignature {
	public final static String SIGN_ALGORITHM_NONE_WITH_ECDSA = "NONEwithECDSA";
	public final static String SIGN_ALGORITHM_RIPEMD160_WITH_ECDSA = "RIPEMD160withECDSA";
	public final static String SIGN_ALGORITHM_SHA1_WITH_ECDSA = "SHA1withECDSA";
	public final static String SIGN_ALGORITHM_SHA224_WITH_ECDSA = "SHA224withECDSA";
	public final static String SIGN_ALGORITHM_SHA256_WITH_ECDSA = "SHA256withECDSA";
	public final static String SIGN_ALGORITHM_SHA384_WITH_ECDSA = "SHA384withECDSA";
	public final static String SIGN_ALGORITHM_SHA512_WITH_ECDSA = "SHA512withECDSA";
	
	public final static int KEY_BIT_LEN_192 = 192;
	public final static int KEY_BIT_LEN_239 = 239;
	public final static int KEY_BIT_LEN_256 = 256;
	
	
	static {
		BouncyCastle.initProvider();
	};

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

	public PrivateKey decodePrivateKey(byte[] encodedKey) throws CryptoException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
			
			return keyFactory.generatePrivate(keySpec);
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
	
	public PublicKey decodePublicKey(byte[] encodedKey) throws CryptoException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
			
			return keyFactory.generatePublic(keySpec);
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
	
	
	private static KeyPairGenerator createKeyPairGenerator(int keyBitLen) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(
				"prime".concat(String.valueOf(keyBitLen)).concat("v1"));
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
		
		SecureRandom random = createSecureRandom();
		keyGen.initialize(ecSpec, random);
		
		return keyGen;
	}
	
	private static SecureRandom createSecureRandom() throws NoSuchAlgorithmException {
		return SecureRandom.getInstance("SHA1PRNG");
	}
	
}
