 package net.jeebiz.crypto;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
 /**
  * @title: KeyPairDecoder.java
  * @package net.jeebiz.crypto
  * @fescription: TODO(添加描述)
  */
 public interface KeyPairDecoder {


	 public String decodeByPublicKey(String encryptedText, String base64PublicKeyText) throws GeneralSecurityException;
	 
	 public String decode(String encryptedText, PublicKey publicKey) throws GeneralSecurityException;

	 public String decodeByPrivateKey(String encryptedText, String base64PrivateKeyText) throws GeneralSecurityException;
	 
	 public String decode(String encryptedText, PrivateKey privateKey) throws GeneralSecurityException;
	 
	 public byte[] decodeByPublicKey(byte[] encryptedBytes, String base64PublicKeyText) throws GeneralSecurityException;
	 
	 public byte[] decode(byte[] encryptedBytes, PublicKey publicKey) throws GeneralSecurityException;

	 public byte[] decodeByPrivateKey(byte[] encryptedBytes, String base64PrivateKeyText) throws GeneralSecurityException;
	 
	 public byte[] decode(byte[] encryptedBytes, PrivateKey privateKey) throws GeneralSecurityException;
	 
}

 

