package de.homelabs.moonrat.javacrypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.homelabs.moonrat.javacrypto.helper.AESHelper;
import de.homelabs.moonrat.javacrypto.helper.CryptKeyHolder;
import de.homelabs.moonrat.javacrypto.helper.RSAHelper;

class MrJavaCryptoApplicationTests {

	private static final Logger log = LoggerFactory.getLogger(MrJavaCryptoApplicationTests.class);
	
	String iv = "1234567890123456";	
	String skey = "12345678901234567890123456789012";
	String input = "$$00123";
	String testVector = "YyPRZBKRAyzvg1KncL8mhg==";

	
	@Test
	void aesEncryptionTest() {
		String encryptedString = "";
		try {
			encryptedString = AESHelper.encrypt(input, skey, iv, true);
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		log.info("encrypted String - {}", encryptedString);
		
		assertEquals(testVector,encryptedString);
	}
	
	@Test
	void aesDecryptionTest() {
		String decryptedString = "";
		
		try {
			decryptedString = AESHelper.decrypt(testVector, skey, iv, true);
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		log.info("decrypted String - {}", decryptedString);
		
		assertEquals(input,decryptedString);
	}
	
	@Test
	void rsaEncryptionAndDecryptionTest() 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, 
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		
		CryptKeyHolder keyHolder = RSAHelper.createRSAKeys(2048);
		
		String cipherText = RSAHelper.encrypt(testVector, keyHolder.getPublicKey(), true);
		log.info("rsa encrypted string: {}", cipherText);
		
		String cleanText = RSAHelper.decrypt(cipherText, keyHolder.getPrivateKey(), true);
		log.info("rsa decrypted string: {}", cleanText);
		
		assertEquals(testVector, cleanText);
	}
}
