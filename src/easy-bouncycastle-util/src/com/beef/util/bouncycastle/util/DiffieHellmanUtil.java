package com.beef.util.bouncycastle.util;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
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
