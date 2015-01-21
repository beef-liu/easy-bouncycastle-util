package com.beef.util.bouncycastle.junittest;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;

import com.beef.util.bouncycastle.ISignature;
import com.beef.util.bouncycastle.junittest.TestECDSAinJDK7Provider.ECDSABinaryCipher;
import com.beef.util.bouncycastle.sign.ECDSAPrimeCipher;
import com.beef.util.bouncycastle.util.Base58Util;
import com.beef.util.bouncycastle.util.HexUtil;

public class TestSignCipher {

	public void testECDSAPrime2() {
		ECDSAPrimeCipher signature = new ECDSAPrimeCipher();
		
		testSignCipher2(signature, ECDSAPrimeCipher.KEY_BIT_LEN_256, ECDSABinaryCipher.SIGN_ALGORITHM_SHA256_WITH_ECDSA);
	}

	
	@Test
	public void testECDSAPrime() {
		ECDSAPrimeCipher signature = new ECDSAPrimeCipher();
		
		testSignature(signature, ECDSAPrimeCipher.KEY_BIT_LEN_256, ECDSAPrimeCipher.SIGN_ALGORITHM_SHA256_WITH_ECDSA);
	}
	

	public void testSignCipher2(ISignature signature, int keyBitLen, String signAlgo) {
		try {
			KeyPair keyPair = signature.generateKeyPair(keyBitLen);
			
			PrivateKey priKey = keyPair.getPrivate();
			PublicKey pubKey = keyPair.getPublic();
			
			byte[] priKeyBytes = priKey.getEncoded();
			byte[] pubKeyBytes = pubKey.getEncoded();
			
			long beginTime = System.currentTimeMillis();
			int loopCnt = 3000;
			String inputStr = "Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);Cipher cipher = Cipher.getInstance(RC5/CBC/PKCS5Padding);";
			for(int i = 0; i < loopCnt; i ++) {
				//sign
				byte[] input = inputStr.getBytes();
				
				byte[] signBytes = signature.sign(signAlgo, priKeyBytes, input);
				boolean verifySign = signature.verifySign(signAlgo, pubKeyBytes, input, signBytes);
				if(!verifySign) {
					System.out.println("verifySign failed");
				}
			}
			
			System.out.println("testSignCipher2 cost(ms):" + (System.currentTimeMillis() - beginTime));
		} catch(Throwable e) {
			e.printStackTrace();
		}
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
	
}
