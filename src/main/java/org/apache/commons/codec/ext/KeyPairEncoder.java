 package org.apache.commons.codec.ext;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
 /**
  * @title: KeyPairEncoder.java
  * @package org.apache.commons.codec.ext
  * @fescription: TODO(添加描述)
  */
 public interface KeyPairEncoder {
	 
	 public String encodeByPublicKey(String plainText, String base64PublicKeyText) throws GeneralSecurityException;
	 
	 public String encode(String plainText, PublicKey publicKey) throws GeneralSecurityException;

	 public String encodeByPrivateKey(String plainText, String base64PrivateKeyText) throws GeneralSecurityException;
	 
	 public String encode(String plainText, PrivateKey privateKey) throws GeneralSecurityException;
	 
	 public byte[] encodeByPublicKey(byte[] plainBytes, String base64PublicKeyText) throws GeneralSecurityException;
	 
	 public byte[] encode(byte[] plainBytes, PublicKey publicKey) throws GeneralSecurityException;

	 public byte[] encodeByPrivateKey(byte[] plainBytes, String base64PrivateKeyText) throws GeneralSecurityException;
	 
	 public byte[] encode(byte[] plainBytes, PrivateKey privateKey) throws GeneralSecurityException;
	 
}

 

