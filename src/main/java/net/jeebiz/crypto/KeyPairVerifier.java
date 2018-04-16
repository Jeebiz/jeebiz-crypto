package net.jeebiz.crypto;

import java.security.GeneralSecurityException;

/**
* @title: KeyPairVerifier.java
* @package net.jeebiz.crypto
* @fescription: TODO(添加描述)
*/
public interface KeyPairVerifier {

	public String sign(byte[] encryptedBytes, String base64PrivateKeyText) throws GeneralSecurityException;
	
	public boolean verify(byte[] encryptedBytes, String base64PublicKeyText, String sign) throws GeneralSecurityException;
	
	public boolean verify(byte[] encryptedBytes, byte[] base64PublicKeyText, String sign) throws GeneralSecurityException;
	
}
