package com.beef.util.bouncycastle.junittest;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import com.beef.util.bouncycastle.BinKeyPair;
import com.beef.util.bouncycastle.CryptoException;
import com.beef.util.bouncycastle.ISignature;
import com.beef.util.bouncycastle.util.Base58Util;
import com.beef.util.bouncycastle.util.HexUtil;

public class TestECDSAinJDK7Provider {
	
	public void testECDSABinary2() {
		ECDSABinaryCipher signature = new ECDSABinaryCipher();
		
		testSignature(signature, ECDSABinaryCipher.KEY_BIT_LEN_283, ECDSABinaryCipher.SIGN_ALGORITHM_SHA256_WITH_ECDSA);
	}
	
	public void testECDSABinary() {
		ECDSABinaryCipher signature = new ECDSABinaryCipher();
		
		testSignature(signature, ECDSABinaryCipher.KEY_BIT_LEN_283, ECDSABinaryCipher.SIGN_ALGORITHM_SHA256_WITH_ECDSA);
	}

	
	private void testSignature(ISignature signature, int keyBitLen, String signAlgo) {
		try {
			
			KeyPair keyPair = signature.generateKeyPair(keyBitLen);
			
			PrivateKey priKey = keyPair.getPrivate();
			PublicKey pubKey = keyPair.getPublic();
			
			System.out.println("private key format:" + priKey.getFormat());
			System.out.println("public key format:" + pubKey.getFormat());

			System.out.println("private key algo:" + priKey.getAlgorithm());
			System.out.println("public key algo:" + pubKey.getAlgorithm());
			
			byte[] priKeyBytes = priKey.getEncoded();
			byte[] pubKeyBytes = pubKey.getEncoded();
			
			System.out.println("private key len:" + priKeyBytes.length);
			System.out.println("public key len:" + pubKeyBytes.length);
			
			System.out.println("private key(hex   ):" + HexUtil.toHexString(priKeyBytes));
			System.out.println("private key(base58):" + new String(Base58Util.encode(priKeyBytes)));
			System.out.println("public key:" + HexUtil.toHexString(pubKeyBytes));
			
			//sign
			String inputStr = "Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);";
			byte[] input = inputStr.getBytes();
			
			byte[] signBytes = signature.sign(signAlgo, priKeyBytes, input);
			System.out.println("signBytes.len:" + signBytes.length);
			System.out.println("sign(hex   ):" + HexUtil.toHexString(signBytes));
			System.out.println("sign(base58):" + new String(Base58Util.encode(signBytes)));
			
			boolean verifySign = signature.verifySign(signAlgo, pubKeyBytes, input, signBytes);
			System.out.println("verify sign:" + verifySign);
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * This class is only supported by java7+ 
	 * @author XingGu Liu
	 *
	 */
	public static class ECDSABinaryCipher implements ISignature {
		public final static String SIGN_ALGORITHM_SHA256_WITH_ECDSA = "SHA256withECDSA";
		
		public final static int KEY_BIT_LEN_163 = 163;
		public final static int KEY_BIT_LEN_233 = 233;
		public final static int KEY_BIT_LEN_283 = 283;
		public final static int KEY_BIT_LEN_409 = 409;
		public final static int KEY_BIT_LEN_571 = 571;


		@Override
		public byte[] sign(String signAlgorithm, byte[] encodedKey, byte[] input) throws CryptoException {
			return sign(signAlgorithm, encodedKey, input, 0, input.length);
		}
		
		@Override
		public byte[] sign(String signAlgorithm, byte[] encodedKey, byte[] input, int offset, int len) throws CryptoException {
			try {
				PrivateKey privateKey = decodePrivateKey(encodedKey);

				SecureRandom random = createSecureRandom();
				
				//Signature sign = Signature.getInstance("SHA1withECDSA");
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
			return verifySign(signAlgorithm, encodedKey, input, 
					0, input.length, signature, 0, signature.length);
		}
		
		@Override
		public boolean verifySign(String signAlgorithm, byte[] encodedKey, 
				byte[] input, int inputOffset, int inputLen, 
				byte[] signature, int signOffset, int signLen
				) throws CryptoException {
			try {
				PublicKey publicKey = decodePublicKey(encodedKey);

				//Signature sign = Signature.getInstance("SHA1withECDSA");
				Signature sign = Signature.getInstance(signAlgorithm);
				sign.initVerify(publicKey);
				
				sign.update(input, inputOffset, inputLen);
				return sign.verify(signature, signOffset, signLen);
			} catch(Throwable e) {
				throw new CryptoException(e);
			}
		}

		@Override
		public BinKeyPair generateEncodedKeyPair(int keyBitLen) throws CryptoException {
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
		public KeyPair generateKeyPair(int keyBitLen) throws CryptoException {
			try {
				return createKeyPairGenerator(keyBitLen).generateKeyPair();
			} catch(Throwable e) {
				throw new CryptoException(e);
			}
		}

		@Override
		public List<KeyPair> generateKeyPairs(int keyBitLen, int count) throws CryptoException {
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
		
		public PrivateKey decodePrivateKey(byte[] encodedKey) throws CryptoException {
			try {
				KeyFactory keyFactory = KeyFactory.getInstance("EC");
				PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
				
				return keyFactory.generatePrivate(keySpec);
			} catch(Throwable e) {
				throw new CryptoException(e);
			}
		}
		
		public PublicKey decodePublicKey(byte[] encodedKey) throws CryptoException {
			try {
				KeyFactory keyFactory = KeyFactory.getInstance("EC");
				X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
				
				return keyFactory.generatePublic(keySpec);
			} catch(Throwable e) {
				throw new CryptoException(e);
			}
		}

		private static KeyPairGenerator createKeyPairGenerator(int keyBitLen) throws CryptoException, NoSuchAlgorithmException {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
			SecureRandom random = createSecureRandom();
			keyPairGen.initialize(keyBitLen, random);
			
			return keyPairGen;
		}
		
		private static SecureRandom createSecureRandom() throws NoSuchAlgorithmException {
			return SecureRandom.getInstance("SHA1PRNG");
		}
		
	}
	
}
