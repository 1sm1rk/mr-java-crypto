package de.homelabs.moonrat.javacrypto.helper;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSAHelper {
	static Logger log = LoggerFactory.getLogger(RSAHelper.class);
	private static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
	
	/**
	 * 
	 * @param keySize
	 * @return
	 */
	public static CryptKeyHolder createRSAKeys(int keySize) {
		KeyPairGenerator generator;
		
		try {
			generator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			log.error(e.getMessage());
			return new CryptKeyHolder(e.getMessage(), true);
		}
		
		generator.initialize(keySize);
		KeyPair pair = generator.generateKeyPair();
			
		return new CryptKeyHolder(pair.getPrivate(), pair.getPublic(),"",false);
	}
	
	/**
	 * 
	 * @param input
	 * @param publicKey
	 * @param encodeBase64
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static String encrypt(String input, PublicKey publicKey, boolean encodeBase64) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		return new String(encrypt(input.getBytes(), publicKey, encodeBase64));
	}
	
	/**
	 * 
	 * @param input
	 * @param publicKey
	 * @param encodeBase64
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public static byte[] encrypt(byte[] input, PublicKey publicKey, boolean encodeBase64) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		//cipher
		Cipher encryptCipher = Cipher.getInstance(ALGORITHM);
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		
		//decode text		
		if (encodeBase64) {
			return Base64.encodeBase64(encryptCipher.doFinal(input));
		} else {
			return encryptCipher.doFinal(input);
		}
	}
	
	/**
	 * 
	 * @param cipherText
	 * @param privateKey
	 * @param iv
	 * @param isBase64
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static String decrypt(String cipherText, PrivateKey privateKey, boolean isBase64) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		return new String(decrypt(cipherText.getBytes(), privateKey, isBase64));
	}
	
	/**
	 * 
	 * @param cipherText
	 * @param privateKey
	 * @param iv
	 * @param isBase64
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte[] decrypt(byte[] cipherText, PrivateKey privateKey, boolean isBase64) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		//cipher
		Cipher decryptCipher = Cipher.getInstance(ALGORITHM);
		decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
		
		//decode text		
		if (isBase64) {
			if (Base64.isBase64(cipherText))
				return decryptCipher.doFinal(Base64.decodeBase64(cipherText));
			else {
				throw new InvalidAlgorithmParameterException("cipher text is not base64 encoded");
			}
		} else {
			return decryptCipher.doFinal(cipherText);
		}
	}
}
