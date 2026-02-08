package de.homelabs.moonrat.javacrypto.helper;

import java.security.AsymmetricKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
 * //TODO: boundaries check
 * test side online
 * https://www.devglan.com/online-tools/rsa-encryption-decryption
 * https://medium.com/@danaschoeman/rsa-encryption-padding-with-java-examples-020c4e59ca5e
 */
public class RSAHelper {
	static Logger logger = LoggerFactory.getLogger(RSAHelper.class);
	private static final String ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	
	/**
	 * 
	 * @param keySize
	 * @return
	 */
	public static Optional<CryptKeyHolder> createRSAKeys(int keySize) {
		KeyPairGenerator generator;
		
		try {
			generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(keySize);
			KeyPair pair = generator.generateKeyPair();
				
			return Optional.of(new CryptKeyHolder(pair.getPrivate(), pair.getPublic(), LocalDateTime.now()));
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getMessage());
			return Optional.empty();
		}
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
	public static Optional<String> encrypt(String input, AsymmetricKey key, boolean encodeBase64) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		
		Optional<byte[]> resp = encrypt(input.getBytes(), key, encodeBase64);
		if (resp.isPresent())
			return Optional.of(new String(resp.get()));
		else
			return Optional.empty();
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
	public static Optional<byte[]> encrypt(byte[] input, AsymmetricKey key, boolean encodeBase64) {
		
		try {
			//cipher
			Cipher encryptCipher = Cipher.getInstance(ALGORITHM);
			encryptCipher.init(Cipher.ENCRYPT_MODE, key);
			
			//decode text		
			if (encodeBase64) {
				return Optional.of(Base64.getEncoder().encode(encryptCipher.doFinal(input)));
			} else {
				return Optional.of(encryptCipher.doFinal(input));
			}
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
			return Optional.empty();
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
	public static Optional<String> decrypt(String cipherText, AsymmetricKey key, boolean isBase64) {
		Optional<byte[]> resp = decrypt(cipherText.getBytes(), key, isBase64);
		
		if (resp.isPresent()) 
			return Optional.of(new String(resp.get()));
		else
			return Optional.empty();
			
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
	public static Optional<byte[]> decrypt(byte[] cipherText, AsymmetricKey key, boolean isBase64) {
		
		try {
			//cipher
			Cipher decryptCipher = Cipher.getInstance(ALGORITHM);
			decryptCipher.init(Cipher.DECRYPT_MODE, key);
			
			//decode text		
			if (isBase64) {
				return Optional.of(decryptCipher.doFinal(Base64.getDecoder().decode(cipherText)));
				
			} else {
				return Optional.of(decryptCipher.doFinal(cipherText));
			}
		} catch (Exception e) {
			logger.error("cannot decrypt msg");
			return Optional.empty();
		}
	}
}
