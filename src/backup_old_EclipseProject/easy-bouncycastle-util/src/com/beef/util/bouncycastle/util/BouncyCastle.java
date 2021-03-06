package com.beef.util.bouncycastle.util;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastle {
	public final static BouncyCastleProvider Provider = new BouncyCastleProvider();
	
	static {
		initProvider();
	};

	private static void initProvider() {
		if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) 
		{
			Security.addProvider(Provider);
			
			System.out.println("Security.addProvider:" + BouncyCastleProvider.PROVIDER_NAME);
		}
		
	}
	
}
