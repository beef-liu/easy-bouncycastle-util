package com.beef.util.bouncycastle.util;

public class ByteArrayUtil {

	public final static boolean equal(byte[] bytes1, int offset1, byte[] bytes2, int offset2, int len) {
		if((bytes1.length - offset1) < len) {
			return false;
		}
		if((bytes2.length - offset2) < len) {
			return false;
		}
		
		for(int i = 0; i < len; i++) {
			if(bytes1[offset1 + i] != bytes2[offset2 + i]) {
				return false;
			}
		}
		
		return true;
	}
}
