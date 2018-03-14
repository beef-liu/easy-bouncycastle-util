package com.beef.util.bouncycastle.junittest;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

import com.beef.util.bouncycastle.util.Base58Util;

public class TestBase58 {
	private static Random _rand = new Random(System.currentTimeMillis());
	
	@Test
	public void test1() {
		long beginTime = System.currentTimeMillis();
		
		try {
			int byteLen = 32;
			int loopCnt = 10000;
			
			for(int i = 0; i < loopCnt; i++) {
				testBase58(byteLen);
			}
		} catch(Throwable e) {
			e.printStackTrace();
		}
		
		System.out.println("cost:" + (System.currentTimeMillis() - beginTime));
	}
	
	private void testBase58(int byteLen) throws UnsupportedEncodingException {
		byte[] bytes = createRandomBytes(byteLen);
		
		String s = Base58Util.encode(bytes);
		byte[] bytesDec = Base58Util.decode(s);

		boolean isEqual = Arrays.equals(bytes, bytesDec);
		if(bytes.length != bytesDec.length) {
			isEqual = false;
		}
		
		if(!isEqual) {
			System.out.println("fail:" + s);
		} else {
			System.out.println(s);
		}
		
	}
	
	
	
	private static byte[] createRandomBytes(int len) {
		byte[] bytes = new byte[len];
		
		_rand.nextBytes(bytes);
		
		return bytes;
	}

}
