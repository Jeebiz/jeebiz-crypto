package org.apache.commons.codec.ext;

import java.security.GeneralSecurityException;

/**
* @title: KeyPairVerifier.java
* @package org.apache.commons.codec.ext
* @fescription: TODO(添加描述)
*/
public interface KeyPairVerifier {

	public String sign(byte[] encryptedBytes, String base64PrivateKeyText) throws GeneralSecurityException;
	
	public boolean verify(byte[] encryptedBytes, String base64PublicKeyText, String sign) throws GeneralSecurityException;
	
	public boolean verify(byte[] encryptedBytes, byte[] base64PublicKeyText, String sign) throws GeneralSecurityException;
	
}
