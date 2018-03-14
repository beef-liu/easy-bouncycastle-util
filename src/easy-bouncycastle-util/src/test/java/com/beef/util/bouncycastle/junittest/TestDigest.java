package com.beef.util.bouncycastle.junittest;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

import com.beef.util.bouncycastle.util.Base58Util;
import com.beef.util.bouncycastle.util.BouncyCastle;
import com.beef.util.bouncycastle.util.ByteArrayUtil;
import com.beef.util.bouncycastle.util.DigestUtil;

public class TestDigest {
//	static {
//		BouncyCastle.initProvider();
//	}
	
	private Random _rand = new Random(System.currentTimeMillis());

	public void testCost() {
		try {
			long beginTime = System.currentTimeMillis();
			
			String input = "testtesttesttesttesttest";
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			
			byte[] buffer = input.getBytes();
			
			int loopCnt = 10000;
			for(int i = 0; i < loopCnt; i++) {
				buffer = sha.digest(buffer);
			}
			
			System.out.println("cost:" + (System.currentTimeMillis() - beginTime));
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}

	public void test4() {
		byte[] buffer1 = new byte[128];
		byte[] buffer2 = new byte[128];
		
		Arrays.fill(buffer1, (byte)0);
		Arrays.fill(buffer2, (byte)0);
		
		int loopCnt = 1000000;

		{
			long beginTime = System.currentTimeMillis();
			for(int i = 0; i < loopCnt; i++) {
				ByteArrayUtil.equal(buffer1, 0, buffer2, 0, buffer1.length);
			}
			System.out.println("equal1 test(cost):" + (System.currentTimeMillis() - beginTime));
		}
	}
	
	public void test3() {
		try {
			byte[] input = "test1".getBytes();
			
			{
				byte[] buffer = new byte[128];
				int signLen = DigestUtil.ripemd160(input, 0, input.length, buffer, 0, buffer.length);
				System.out.println("sign1:" + Base58Util.encode(buffer, 0, signLen));
			}

			{
				byte[] buffer = new byte[128];
				System.arraycopy(input, 0, buffer, 0, input.length);
				int signLen = DigestUtil.ripemd160(buffer, 0, input.length, buffer, 0, buffer.length);
				System.out.println("sign2:" + Base58Util.encode(buffer, 0, signLen));
			}
			
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	public void test2() {
		try {
			byte[] input = "test".getBytes();
			byte[] buffer = new byte[128];
			int offset = 12;
			 
			byte[] sign = DigestUtil.sha256(input);
			System.out.println("sign1:" + Base58Util.encode(sign));
			
			int signLen = DigestUtil.md5(input, 0, input.length, buffer, offset, buffer.length - offset);
			System.out.println("sign2:" + Base58Util.encode(buffer, offset, signLen));
			
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	@Test
	public void test1() {
		try {
			byte[] input = "test".getBytes();
			MessageDigest md = MessageDigest.getInstance("RIPEMD160", BouncyCastle.Provider);
			byte[] sign;
			
			{
				sign = md.digest(input);
				System.out.println("ripemd160: " + Base58Util.encode(sign));
			}

			{
				byte[] input2 = new byte[input.length * 2];
				int offset = _rand.nextInt(input2.length - input.length);
				System.arraycopy(input, 0, input2, offset, input.length);
				
				md.update(input2, offset, input.length);
				sign = md.digest();
				System.out.println("ripemd160: " + Base58Util.encode(sign));
			}
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	public void testRipemd160() {
		try {
			String input = "test";
			byte[] sign = DigestUtil.ripemd160(input.getBytes());
			System.out.println("ripemd160: " + Base58Util.encode(sign));
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
	
	public void testSha256() {
		try {
			String input = "test";
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			
			byte[] sign = sha.digest(input.getBytes());
			System.out.println("sha256: " + Base58Util.encode(sign));
		} catch(Throwable e) {
			e.printStackTrace();
		}
	}
}
