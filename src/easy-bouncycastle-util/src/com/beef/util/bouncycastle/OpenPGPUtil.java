package com.beef.util.bouncycastle;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;

public class OpenPGPUtil {

	static {
		initProvider();
	};

	private static void initProvider() {
		if(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
			
			System.out.println("Security.addProvider:" + BouncyCastleProvider.PROVIDER_NAME);
		}
		
	}

	public static void encrypt(File publicKey, File input, File output)
			throws NoSuchProviderException, IOException, PGPException {
		boolean armor = false;
		boolean withIntegrityCheck = true;
		
		InputStream publicKeyInput = null;
		
		try {
			publicKeyInput = new BufferedInputStream(new FileInputStream(publicKey));
			encrypt(publicKeyInput, input, output, armor, withIntegrityCheck);
		} finally {
			publicKeyInput.close();
		}
	}

	public static void encrypt(InputStream publicKey, File input, File output)
			throws NoSuchProviderException, IOException, PGPException {
		boolean armor = false;
		boolean withIntegrityCheck = true;

		encrypt(publicKey, input, output, armor, withIntegrityCheck);
	}
	
	public static void encrypt(InputStream publicKey, File input, File output, 
			boolean armor, boolean withIntegrityCheck)
			throws IOException, NoSuchProviderException, PGPException {
		OutputStream out = null;
		try {
			out = new BufferedOutputStream(new FileOutputStream(output));
			PGPPublicKey encKey = readPublicKey(publicKey);
			encryptFile(encKey, input, out, armor, withIntegrityCheck);
		} finally {
			out.close();
		}
	}

	public static void decrypt(InputStream privateKey, String password, 
			File input, File output) throws NoSuchProviderException, IOException, PGPException {
		InputStream inputFile = null;

		try {
			inputFile = new BufferedInputStream(new FileInputStream(input));

			decryptFile(privateKey, password.toCharArray(), inputFile, output);
		} finally {
			try {
				inputFile.close();
			} catch (Throwable e) {
			}
		}
	}
	
	public static void decrypt(File privateKey, String password, 
			File input, File output) throws NoSuchProviderException, IOException, PGPException {
		InputStream inputKey = null;
		InputStream inputFile = null;

		try {
			inputKey = new BufferedInputStream(new FileInputStream(privateKey));
			inputFile = new BufferedInputStream(new FileInputStream(input));

			decryptFile(inputKey, password.toCharArray(), inputFile, output);
		} finally {
			try {
				inputKey.close();
			} catch (Throwable e) {
			}
			try {
				inputFile.close();
			} catch (Throwable e) {
			}
		}
	}

	public static void decrypt(File privateKey, char[] passwd, 
			File input, File output) throws IOException, NoSuchProviderException, PGPException {
		InputStream in = null;
		InputStream keyIn = null;

		try {
			in = new BufferedInputStream(new FileInputStream(input));
			keyIn = new BufferedInputStream(new FileInputStream(privateKey));
			// out = new FileOutputStream(outputFile);

			decryptFile(keyIn, passwd, in, output);
		} finally {
			try {
				keyIn.close();
			} catch (Throwable e) {
			}
			try {
				in.close();
			} catch (Throwable e) {
			}
		}
	}
	
	/*
	 * public static void decrypt(InputStream privateKey, String password,
	 * InputStream input, OutputStream output) throws NoSuchProviderException,
	 * IOException { decryptFile(input, privateKey, password.toCharArray(),
	 * output); }
	 */

	protected static byte[] compressFile(File file, int algorithm)
			throws IOException {
		PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
				algorithm);
		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		try {
			PGPUtil.writeFileToLiteralData(comData.open(bOut),
					PGPLiteralData.BINARY, file);
		} finally {
			comData.close();
		}
		
		return bOut.toByteArray();
	}

	protected static PGPPrivateKey findSecretKey(
			PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
			throws PGPException, NoSuchProviderException {
		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey == null) {
			return null;
		}

		return pgpSecKey
				.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
						.setProvider("BC").build(pass));
	}

	protected static PGPPublicKey readPublicKey(File file) throws IOException,
			PGPException {
		InputStream keyIn = null;
		
		try {
			keyIn = new BufferedInputStream(new FileInputStream(file));
			PGPPublicKey pubKey = readPublicKey(keyIn);
			return pubKey;
		} finally {
			keyIn.close();
		}
	}

	protected static PGPPublicKey readPublicKey(InputStream input)
			throws IOException, PGPException {
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
				PGPUtil.getDecoderStream(input),
				new JcaKeyFingerprintCalculator());

		//
		// we just loop through the collection till we find a key suitable for
		// encryption, in the real
		// world you would probably want to be a bit smarter about this.
		//

		Iterator keyRingIter = pgpPub.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

			Iterator keyIter = keyRing.getPublicKeys();
			while (keyIter.hasNext()) {
				PGPPublicKey key = (PGPPublicKey) keyIter.next();

				if (key.isEncryptionKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException(
				"Can't find encryption key in key ring.");
	}

	protected static PGPSecretKey readSecretKey(File file) throws IOException,
			PGPException {
		InputStream keyIn = new BufferedInputStream(new FileInputStream(file));
		
		try {
			PGPSecretKey secKey = readSecretKey(keyIn);
			return secKey;
		} finally {
			keyIn.close();
		}
	}

	protected static PGPSecretKey readSecretKey(InputStream input)
			throws IOException, PGPException {
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(input),
				new JcaKeyFingerprintCalculator());

		//
		// we just loop through the collection till we find a key suitable for
		// encryption, in the real
		// world you would probably want to be a bit smarter about this.
		//

		Iterator keyRingIter = pgpSec.getKeyRings();
		while (keyRingIter.hasNext()) {
			PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

			Iterator keyIter = keyRing.getSecretKeys();
			while (keyIter.hasNext()) {
				PGPSecretKey key = (PGPSecretKey) keyIter.next();

				if (key.isSigningKey()) {
					return key;
				}
			}
		}

		throw new IllegalArgumentException(
				"Can't find signing key in key ring.");
	}

	/**
	 * decrypt the passed in message stream
	 * @throws PGPException 
	 */
	private static void decryptFile(
			InputStream privateKey,
			char[] passwd,
			// String defaultFileName,
			InputStream input, File output) throws IOException, NoSuchProviderException, PGPException {
		input = PGPUtil.getDecoderStream(input);

		JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(input);
		PGPEncryptedDataList enc;

		Object o = pgpF.nextObject();
		//
		// the first object might be a PGP marker packet.
		//
		if (o instanceof PGPEncryptedDataList) {
			enc = (PGPEncryptedDataList) o;
		} else {
			enc = (PGPEncryptedDataList) pgpF.nextObject();
		}

		//
		// find the secret key
		//
		Iterator it = enc.getEncryptedDataObjects();
		PGPPrivateKey sKey = null;
		PGPPublicKeyEncryptedData pbe = null;
		PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
				PGPUtil.getDecoderStream(privateKey),
				new JcaKeyFingerprintCalculator());

		while (sKey == null && it.hasNext()) {
			pbe = (PGPPublicKeyEncryptedData) it.next();

			sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
		}

		if (sKey == null) {
			throw new IllegalArgumentException(
					"secret key for message not found.");
		}

		InputStream clear = pbe
				.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
						.setProvider("BC").build(sKey));

		JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

		Object message = plainFact.nextObject();

		if (message instanceof PGPCompressedData) {
			PGPCompressedData cData = (PGPCompressedData) message;
			JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(
					cData.getDataStream());

			message = pgpFact.nextObject();
		}

		if (message instanceof PGPLiteralData) {
			PGPLiteralData ld = (PGPLiteralData) message;

			/*
			 * String outFileName = ld.getFileName(); if
			 * (outFileName.length() == 0) { outFileName = defaultFileName;
			 * }
			 */

			InputStream unc = ld.getInputStream();
			// OutputStream fOut = new BufferedOutputStream(new
			// FileOutputStream(outFileName));
			OutputStream fOut = new BufferedOutputStream(
					new FileOutputStream(output));

			try {
				Streams.pipeAll(unc, fOut);
			} finally {
				fOut.close();
			}
		} else if (message instanceof PGPOnePassSignatureList) {
			throw new PGPException(
					"encrypted message contains a signed message - not literal data.");
		} else {
			throw new PGPException(
					"message is not a simple encrypted file - type unknown.");
		}

		if (pbe.isIntegrityProtected()) {
			if (!pbe.verify()) {
				throw new PGPException("message failed integrity check");
			} else {
				System.out.println("message integrity check passed");
			}
		} else {
			System.out.println("no message integrity check");
		}
	}

	private static void encryptFile(
			PGPPublicKey encKey, File input, OutputStream out, 
			boolean armor, boolean withIntegrityCheck) throws IOException,
			NoSuchProviderException, PGPException {
		if (armor) {
			out = new ArmoredOutputStream(out);
		}

		try {
			byte[] bytes = compressFile(input, CompressionAlgorithmTags.ZIP);

			PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
					new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
							.setWithIntegrityPacket(withIntegrityCheck)
							.setSecureRandom(new SecureRandom())
							.setProvider("BC"));

			encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(
					encKey).setProvider("BC"));

			OutputStream cOut = encGen.open(out, bytes.length);

			try {
				cOut.write(bytes);
			} finally {
				cOut.close();
			}
		} finally {
			if (armor) {
				out.close();
			}
		}
	}

	private static byte[] readFile(File file) throws IOException {
		FileInputStream input = null;

		try {
			input = new FileInputStream(file);
			return readFile(input);
		} finally {
			try {
				input.close();
			} catch (Throwable e) {
			}
		}
	}

	private static byte[] readFile(InputStream input) throws IOException {
		byte[] temp = new byte[1024 * 4];

		ByteArrayOutputStream output = new ByteArrayOutputStream();
		int readLen;

		while (true) {
			readLen = input.read(temp);

			if (readLen < 0) {
				break;
			}

			if (readLen > 0) {
				output.write(temp, 0, readLen);
			}
		}

		return output.toByteArray();
	}
}
