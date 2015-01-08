package com.beef.util.bouncycastle.junittest;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;

import com.beef.util.bouncycastle.OpenPGPUtil;

public class OpenPGPUtilTest {
	private final static String TestPassphrase = "xko33h73";

	@Test
	public void testGnuPG() {
		File testDir = new File("testData/gnupg");
		File txtFile = new File(testDir,"test.txt");
		
		File privateKeyFile = new File(testDir, "prikey.txt");
		File publicKeyFile = new File(testDir, "pubkey.txt");
		
		File encFile = new File(testDir, "test_enc.txt");
		File decFile = new File(testDir, "test_dec.txt");

		try {
			//encrypt
			OpenPGPUtil.encrypt(publicKeyFile, txtFile, encFile);
			
			//decrypt
			OpenPGPUtil.decrypt(privateKeyFile, TestPassphrase, encFile, decFile);
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}

}
