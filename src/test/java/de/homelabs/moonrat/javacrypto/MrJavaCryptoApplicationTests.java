package de.homelabs.moonrat.javacrypto;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.homelabs.moonrat.javacrypto.helper.AESHelper;
import de.homelabs.moonrat.javacrypto.helper.CryptKeyHolder;
import de.homelabs.moonrat.javacrypto.helper.RSAHelper;

public class MrJavaCryptoApplicationTests {

	private static final Logger log = LoggerFactory.getLogger(MrJavaCryptoApplicationTests.class);
	
	//String iv = "1234567890123456";	
	//private static final String skey = "12345678901234567890123456789012";
	private static final String input = "$$00123";
	private static final String testVector = "YyPRZBKRAyzvg1KncL8mhg==";

	
	@Test
	public void aesEncryptionAndDecryptionTest() {
		SecretKey key = AESHelper.generateKeys().orElseThrow();
		byte[] nonce = AESHelper.generateNonce();
		
		byte[] encryptedBuffer = AESHelper.encrypt(input.getBytes(), key, nonce, true).orElseThrow();
		
				
		log.info("encrypted String - {}", new String(encryptedBuffer));
		
		//assertEquals(testVector,new String(encryptedBuffer));
	
		byte[] decryptedString = AESHelper.decrypt(encryptedBuffer, key, true).orElseThrow();
		log.info("decrypted String - {}", new String(decryptedString));
		
		assertEquals(input, new String(decryptedString));
	}
	
	@Test
	public void rsaEncryptionAndDecryptionTest() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		Optional<CryptKeyHolder> oKeyHolder = RSAHelper.createRSAKeys(4096);
		CryptKeyHolder keyHolder = oKeyHolder.orElseThrow();
		
		String cipherText = RSAHelper.encrypt(testVector, keyHolder.publicKey(), true).orElseThrow();
		log.info("rsa encrypted string: {}", cipherText);
		
		String cleanText = RSAHelper.decrypt(cipherText, keyHolder.privateKey(), true).get();
		log.info("rsa decrypted string: {}", cleanText);
		
		assertEquals(testVector, cleanText);
	}
}
