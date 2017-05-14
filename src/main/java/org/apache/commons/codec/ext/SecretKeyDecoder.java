package org.apache.commons.codec.ext;

import java.security.GeneralSecurityException;
/**
 * 
 * @description:密钥解密算法接口
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-26
 */
public interface SecretKeyDecoder {
	
	public String decode(String encryptedText,String key) throws GeneralSecurityException ;
	public String decode(String encryptedText,byte[] key) throws GeneralSecurityException ;
	public byte[] decode(byte[] encryptedBytes,String key) throws GeneralSecurityException;
	public byte[] decode(byte[] encryptedBytes,byte[] key) throws GeneralSecurityException;

}
