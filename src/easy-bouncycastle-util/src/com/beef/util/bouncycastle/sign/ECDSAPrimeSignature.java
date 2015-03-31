package com.beef.util.bouncycastle.sign;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import com.beef.util.bouncycastle.CryptoException;
import com.beef.util.bouncycastle.util.BouncyCastle;

/**
 * reference doc: http://www.bouncycastle.org/wiki/pages/viewpage.action?pageId=362269
 * @author XingGu Liu
 *
 */
public class ECDSAPrimeSignature extends AbstractSignature {
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
	
	
//	static {
//		BouncyCastle.initProvider();
//	};


	@Override
	public PrivateKey decodePrivateKey(byte[] encodedKey) throws CryptoException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", BouncyCastle.Provider);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
			
			return keyFactory.generatePrivate(keySpec);
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
	
	@Override
	public PublicKey decodePublicKey(byte[] encodedKey) throws CryptoException {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", BouncyCastle.Provider);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
			
			return keyFactory.generatePublic(keySpec);
		} catch(Throwable e) {
			throw new CryptoException(e);
		}
	}
	
	
	@Override
	protected KeyPairGenerator createKeyPairGenerator(int keyBitLen) throws CryptoException {
		try {
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(
					"prime".concat(String.valueOf(keyBitLen)).concat("v1"));
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", BouncyCastle.Provider);
			
			SecureRandom random = createSecureRandom();
			keyGen.initialize(ecSpec, random);
			
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
