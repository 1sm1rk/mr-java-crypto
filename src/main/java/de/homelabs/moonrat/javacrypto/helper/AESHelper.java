package de.homelabs.moonrat.javacrypto.helper;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AESHelper {
	private static final Logger logger = LoggerFactory.getLogger(AESHelper.class);
	private static final String ALGORITHM = "AES/GCM/NoPadding";
	private static final int KEY_SIZE = 256;
	private static final int IV_SIZE = 32;
	private static final int TAG_LENGTH_BITS = 128;
	
	
	/**
	 * return AES key derived from a password
	 * 
	 * @param password
	 * @return Optional<SecretKey>
	 */
	public static Optional<SecretKey> getAESKeyFromPassword(String password)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		try {
			SecretKey secret = new SecretKeySpec(password.getBytes(), "AES");
			return Optional.of(secret);
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
		
		return Optional.empty();
	}

	/**
	 * generates a new AES symmetric key for AES/GCM encryption
	 * with a key size of 256 bit
	 * 
	 * @return Optional<SecretKey>
	 */
	public static Optional<SecretKey> generateKeys() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(KEY_SIZE);
			return Optional.of(keyGen.generateKey());
		} catch (Exception e) {
			logger.error(e.getLocalizedMessage());
		}
		
		return Optional.empty();
	}
	
	 /**
     * Generates a random nonce (IV) for AES/GCM encryption.
     *
     * @param size The size of the nonce in bytes.
     * 
     * @return The generated nonce as a byte array.
     */
    public static byte[] generateNonce() {
        byte[] nonce = new byte[IV_SIZE];
        new SecureRandom().nextBytes(nonce); // Fill nonce with random bytes
        return nonce;
    }
    
    /**
	 * AES encrypt an [input] string with [KEY], [ALGORITHM] and [iv]
	 * 
	 * @param input - input 
	 * @param key   - AES/GCM secret key
	 * @param iv    - random nonce (used for alternation)
	 * 
	 * @return returns an AES encoded string, Base64 encoded depending on flag
	 */
    public static Optional<byte[]> encrypt(byte[] input, SecretKey key, byte[] iv, boolean encodeBase64) {
    	//validate
    	if (input == null || key == null || iv == null ) {
    		logger.error("Invalid parameters, input, key or iv are null");
    		return Optional.empty();
    	}
    	
    	if (input.length <= 0) {
    		logger.error("input is empty");
    		return Optional.empty();
    	}
    	
    	//start
    	try {
	        // Initialize cipher in AES-GCM mode
	        Cipher cipher = Cipher.getInstance(ALGORITHM);
	        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
	        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
	
	        // Encrypt the plaintext
	        byte[] encryptedBytes = cipher.doFinal(input);
	
	        // Combine IV and encrypted text and encode them as Base64
	        byte[] combinedIvAndCipherText = new byte[iv.length + encryptedBytes.length];
	        System.arraycopy(iv, 0, combinedIvAndCipherText, 0, iv.length);
	        System.arraycopy(encryptedBytes, 0, combinedIvAndCipherText, iv.length, encryptedBytes.length);
	
	        if (encodeBase64) {
	        	return Optional.of(Base64.getEncoder().encode(combinedIvAndCipherText));
	        } else {
	        	return Optional.of(combinedIvAndCipherText);
	        }
    	} catch (Exception e) {
    		logger.error(e.getLocalizedMessage());
    		return Optional.empty();
    	}
    }
	
    /**
     * decrypt an AES encrypted byte array
     * 
     * @param input
     * @param key
     * @param isBase64
     * @return String decrypted byte array
     */
    public static Optional<byte[]> decrypt(byte[] input, SecretKey key, boolean isBase64) {
    	try {
	    	// decode base64 if needed
	   		byte[] decodedCipherText = isBase64 ? Base64.getDecoder().decode(input) : input;  	
	    		
	        // Extract IV and encrypted text
	        byte[] iv = new byte[IV_SIZE];
	        System.arraycopy(decodedCipherText, 0, iv, 0, iv.length);    
	        byte[] encryptedText = new byte[decodedCipherText.length - IV_SIZE];
	        System.arraycopy(decodedCipherText, IV_SIZE, encryptedText, 0, encryptedText.length);
	
	        // Initialize cipher in AES-GCM mode
	        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
	        Cipher cipher = Cipher.getInstance(ALGORITHM);
	        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
	        
	        // Decrypt the ciphertext
	        byte[] decryptedBytes = cipher.doFinal(encryptedText);
	
	        return Optional.of(decryptedBytes);
    	} catch (Exception e) {
    		logger.error(e.getLocalizedMessage());
    		return Optional.empty();
    	}
    }
}
