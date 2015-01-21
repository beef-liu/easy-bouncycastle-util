package com.beef.util.bouncycastle.junittest;

import org.junit.Test;

import com.beef.util.bouncycastle.BinKeyPair;
import com.beef.util.bouncycastle.sign.ECDSAPrimeCipher;
import com.beef.util.bouncycastle.util.Base58Util;

public class TestKeypair {

	@Test
	public void test1() {
		ECDSAPrimeCipher cipher = new ECDSAPrimeCipher();
		
		try {
			
			BinKeyPair keyPair = cipher.generateEncodedKeyPair(ECDSAPrimeCipher.KEY_BIT_LEN_256);
			
			System.out.println("pubkey(base58):" + Base58Util.encode(keyPair.getPublicKey()));
			System.out.println("prikey(base58):" + Base58Util.encode(keyPair.getPrivateKey()));
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
}
