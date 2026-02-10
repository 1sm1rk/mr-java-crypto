package de.homelabs.moonrat.javacrypto.helper;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;

public record CryptKeyHolder (PrivateKey privateKey, PublicKey publicKey, LocalDateTime timstamp) {};