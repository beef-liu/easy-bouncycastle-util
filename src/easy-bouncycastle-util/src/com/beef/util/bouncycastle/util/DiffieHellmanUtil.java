package com.beef.util.bouncycastle.util;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.DHParameterSpec;

public class DiffieHellmanUtil {
	
	/**
	 * 
	 * @param keyBitSize (must be multiple of 64, and can only range from 512 to 1024 (inclusive))
	 * @return The G(base of exponential function) and P(prime for mod function).
	 * @throws InvalidParameterSpecException
	 * @throws NoSuchAlgorithmException
	 */
	public final static DHParameterSpec createDHParamSpec(int keyBitSize) throws InvalidParameterSpecException, NoSuchAlgorithmException {
		AlgorithmParameterGenerator paramGen = 
				AlgorithmParameterGenerator.getInstance("DH");
		paramGen.init(keyBitSize);
		
		AlgorithmParameters params = paramGen.generateParameters();
		DHParameterSpec paramSpec = params.getParameterSpec(DHParameterSpec.class);
		
		return paramSpec;
	}
	
	public final static BigInteger makeRandomPrivateKey(int keyBitSize) throws NoSuchAlgorithmException {
		byte[] buffer = new byte[keyBitSize / 8];
		
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.nextBytes(buffer);
		
		if((buffer[0] & 0x80) != 0) {
			buffer[0] &= 0x7F;
		}
		
		BigInteger i = new BigInteger(buffer);
		
		return i;
	}
	
	/**
	 * Set the most left bit to 0 when privateKey.length * 8 == keyBitSize.
	 * Because bit length of the private key must be (keyBitSize - 1) in DiffieHellman algorithm.
	 * @param keyBitSize
	 * @param privateKey
	 * @return formatted key
	 */
	public final static BigInteger formalizePrivateKey(int keyBitSize, byte[] privateKey) {
		if((privateKey.length * 8) == keyBitSize) {
			if((privateKey[0] & 0x80) != 0) {
				byte[] buffer = new byte[privateKey.length];
				System.arraycopy(privateKey, 0, buffer, 0, privateKey.length);
				
				buffer[0] &= 0x7F;
				
				return new BigInteger(buffer);
			} else {
				return new BigInteger(privateKey);
			}
		} else {
			return new BigInteger(privateKey);
		}
	}
	
	/**
	 * Calculate the publicKey to exchange. publicKey = G^privateKey mod P
	 * @param paramSpec
	 * @param privateKey
	 * @return
	 */
	public final static BigInteger generatePublicKey(DHParameterSpec paramSpec, BigInteger privateKey) {
		return paramSpec.getG().modPow(privateKey, paramSpec.getP());
	}
	
	/**
	 * Calculate the secretKey. secretKey = publicKeyFromOtherSide^privateKey mod P
	 * @param paramSpec
	 * @param publicKeyOfOtherSide
	 * @param privateKey
	 * @return
	 */
	public final static BigInteger generateSecretKey(DHParameterSpec paramSpec, 
			BigInteger publicKeyFromOtherSide, BigInteger privateKey) {
		return publicKeyFromOtherSide.modPow(privateKey, paramSpec.getP());
	}
	
}
