package de.homelabs.moonrat.javacrypto.helper;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;

public class CryptKeyHolder {
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private LocalDateTime created;
	private String errorMsg;
	private boolean hasError;
	
	//no public constructor
	protected CryptKeyHolder() {
		
	}
	
	protected CryptKeyHolder(String errorMsg,
			boolean hasError) {
		this.privateKey = null;
		this.publicKey = null;
		this.created = LocalDateTime.now();
		this.errorMsg = errorMsg;
		this.hasError = hasError;
	}
	
	protected CryptKeyHolder(PrivateKey privateKey, PublicKey publicKey, String errorMsg,
			boolean hasError) {
		super();
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.created = LocalDateTime.now();
		this.errorMsg = errorMsg;
		this.hasError = hasError;
	}
	
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	protected void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	public PublicKey getPublicKey() {
		return publicKey;
	}
	protected void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	public LocalDateTime getCreated() {
		return created;
	}
	public String getErrorMsg() {
		return errorMsg;
	}
	protected void setErrorMsg(String errorMsg) {
		this.errorMsg = errorMsg;
	}
	public boolean hasError() {
		return hasError;
	}
	protected void setHasError(boolean hasError) {
		this.hasError = hasError;
	}
}
