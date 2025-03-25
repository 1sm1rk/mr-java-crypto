package de.homelabs.moonrat.javacrypto.helper;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AESHelper {
	Logger log = LoggerFactory.getLogger(this.getClass());
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
	
	private AESHelper() {
	}

	/**
	 * return AES key derived from a password
	 * 
	 * @param password
	 * @return SecretKey
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	public static SecretKey getAESKeyFromPassword(String password)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		SecretKey secret = new SecretKeySpec(password.getBytes(), "AES");
		return secret;
	}

	/**
	 * AES encrypt an [input] string with [KEY], [ALGORITHM] and [iv]
	 * 
	 * @param input - input string
	 * @param key   - 32 bit secret key
	 * @param iv    - 16 bit initialisation vector (used for alternation)
	 * @return returns an Base64 AES encoded string
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String encrypt(String input, SecretKey key, IvParameterSpec iv, boolean encodeBase64)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] cipherText = cipher.doFinal(input.getBytes());

		// decide base64 or not
		if (encodeBase64) {
			return new String(Base64.encodeBase64(cipherText));
		} else {
			return new String(cipherText);
		}
	}

	/**
	 * AES encrypt an [input] string with [KEY], [ALGORITHM] and [iv]
	 * 
	 * @param input
	 * @param key
	 * @param iv
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeySpecException
	 */
	public static String encrypt(String input, String key, String iv, boolean encodeBase64)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {

		SecretKey secretKey = AESHelper.getAESKeyFromPassword(key);
		IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
		byte[] cipherText = cipher.doFinal(input.getBytes());

		// decide base64 or not
		if (encodeBase64) {
			return new String(Base64.encodeBase64(cipherText));
		} else {
			return new String(cipherText);
		}
	}

	/**
	 * decrypt an AES encrypted [cipherText] string with [KEY], [ALGORITHM] and [iv]
	 * 
	 * @param cipherText - encrypted string
	 * @param key        - 32 bit secret key
	 * @param iv         - 16 bit initialisation vector (used for alternation)
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public static String decrypt(String cipherText, SecretKey key, IvParameterSpec iv, boolean isBase64)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		

		if (isBase64) {
			if (Base64.isBase64(cipherText))
				return new String(cipher.doFinal(Base64.decodeBase64(cipherText)));
			else {
				throw new InvalidAlgorithmParameterException("cipher text is not base64 encoded");
			}
		} else {
			return new String(cipher.doFinal(cipherText.getBytes()));
		}
	}

	/**
	 * 
	 * @param cipherText
	 * @param key
	 * @param iv
	 * @return
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidKeySpecException
	 */
	public static String decrypt(String cipherText, String key, String iv, boolean isBase64)
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {

		SecretKey secretKey = AESHelper.getAESKeyFromPassword(key);
		IvParameterSpec ivSpec = new IvParameterSpec(iv.getBytes());

		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
		
		if (isBase64) {
			if (Base64.isBase64(cipherText))
				return new String(cipher.doFinal(Base64.decodeBase64(cipherText)));
			else {
				throw new InvalidAlgorithmParameterException("cipher text is not base64 encoded");
			}
		} else {
			return new String(cipher.doFinal(cipherText.getBytes()));
		}
	}
}
