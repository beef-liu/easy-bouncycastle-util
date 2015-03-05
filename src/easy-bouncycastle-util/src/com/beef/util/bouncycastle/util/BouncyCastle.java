package com.beef.util.bouncycastle.util;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastle {
	static {
		initProvider();
	};

	public static void initProvider() {
		//if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) 
		{
			Security.addProvider(new BouncyCastleProvider());
			
			System.out.println("Security.addProvider:" + BouncyCastleProvider.PROVIDER_NAME);
		}
		
	}
	
}
