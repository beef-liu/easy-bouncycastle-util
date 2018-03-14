package com.beef.util.bouncycastle.junittest;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.DHParameterSpec;

import org.junit.Test;

import com.beef.util.bouncycastle.util.Base58Util;
import com.beef.util.bouncycastle.util.ByteArrayUtil;
import com.beef.util.bouncycastle.util.DiffieHellmanUtil;

public class TestDiffieHellman {
	
	@Test
	public void test3() {
		try {
			int keyBitSize = 1024;
			DHParameterSpec paramSpecInit = DiffieHellmanUtil.createDHParamSpec(keyBitSize);

			long beginTime = System.currentTimeMillis();

			for(int i = 0; i < 10; i++) {
				DHParameterSpec paramSpec = new DHParameterSpec(paramSpecInit.getP(), paramSpecInit.getG(), paramSpecInit.getL());
				
				BigInteger x = makeRandomBigIntegerForDH(keyBitSize);
				BigInteger y = makeRandomBigIntegerForDH(keyBitSize);
				
				//BigInteger pubKeyX = DiffieHellmanUtil.generatePublicKey(paramSpec, x);
				BigInteger pubKeyY = DiffieHellmanUtil.generatePublicKey(paramSpec, y);
				
				BigInteger secretKeyX = DiffieHellmanUtil.generateSecretKey(paramSpec, pubKeyY, x);
				//BigInteger secretKeyY = DiffieHellmanUtil.generateSecretKey(paramSpec, pubKeyX, y);
			}
			
			System.out.println("cost(ms):" + (System.currentTimeMillis() - beginTime));
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	public void test2() {
		try {
			int keyBitSize = 1024;
			DHParameterSpec paramSpec = DiffieHellmanUtil.createDHParamSpec(keyBitSize);
			
			BigInteger x = makeRandomBigIntegerForDH(keyBitSize);
			BigInteger y = makeRandomBigIntegerForDH(keyBitSize);
			
			BigInteger pubKeyX = DiffieHellmanUtil.generatePublicKey(paramSpec, x);
			BigInteger pubKeyY = DiffieHellmanUtil.generatePublicKey(paramSpec, y);
			
			BigInteger secretKeyX = DiffieHellmanUtil.generateSecretKey(paramSpec, pubKeyY, x);
			BigInteger secretKeyY = DiffieHellmanUtil.generateSecretKey(paramSpec, pubKeyX, y);
			
			System.out.println("secret key of both side are equal:" + (secretKeyX.equals(secretKeyY)));
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void test1() {
		try {
//			byte b;
//			b = (byte) 0x80;
//			System.out.println("0th bit is 1:" + (((b ) & 0x80) != 0));
//			System.out.println("set 0th bit to 0:" + (b &= 0x7F));
			
			int keyBitSize = 1024;
			
			DHParameterSpec paramSpec = createDHParamSpec(keyBitSize);
			
			//keys of Alice (x is the secret, exchangeX is the public key) -----------
			BigInteger x = makeRandomBigIntegerForDH(keyBitSize);
			BigInteger exchangeX = paramSpec.getG().modPow(x, paramSpec.getP());
			
			//keys of Bob
			BigInteger y = makeRandomBigIntegerForDH(keyBitSize);
			BigInteger exchangeY = paramSpec.getG().modPow(y, paramSpec.getP());
			
			//generate shared key (Alice and Bob exchanged exchangeX and exchangeY)
			BigInteger secretKeyOfAlice = exchangeY.modPow(x, paramSpec.getP());
			BigInteger secretKeyOfBob = exchangeX.modPow(y, paramSpec.getP());
			
			System.out.println("secretKey1.len:" + secretKeyOfAlice.toByteArray().length);
			System.out.println("secretKey2.len:" + secretKeyOfBob.toByteArray().length);
			System.out.println("secretKey1:" + Base58Util.encode(secretKeyOfAlice.toByteArray()));
			System.out.println("secretKey2:" + Base58Util.encode(secretKeyOfBob.toByteArray()));
			
			System.out.println("secret key of both side are equal:" 
					+ ByteArrayUtil.equal(
							secretKeyOfAlice.toByteArray(), 0, 
							secretKeyOfBob.toByteArray(), 0, 
							secretKeyOfAlice.toByteArray().length)
							);
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	private BigInteger makeRandomBigIntegerForDH(int keyBitSize) throws NoSuchAlgorithmException {
		byte[] buffer = new byte[keyBitSize / 8];
		
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.nextBytes(buffer);
		
		if((buffer[0] & 0x80) != 0) {
			buffer[0] &= 0x7F;
		}
		
		BigInteger i = new BigInteger(buffer);
		
		return i;
	}
	
	private DHParameterSpec createDHParamSpec(int keyBitSize) throws InvalidParameterSpecException, NoSuchAlgorithmException {
		AlgorithmParameterGenerator paramGen = 
				AlgorithmParameterGenerator.getInstance("DH");
		//keysize can only range from 512 to 1024
		paramGen.init(keyBitSize);
		
		AlgorithmParameters params = paramGen.generateParameters();
		DHParameterSpec paramSpec = params.getParameterSpec(DHParameterSpec.class);
		
		//bit size of random exponent 
		System.out.println("L:" + paramSpec.getL());
		//base generator
		System.out.println("g:" + paramSpec.getG());
		//prime modulus
		System.out.println("" + paramSpec.getP());
		
		return paramSpec;
	}
}
