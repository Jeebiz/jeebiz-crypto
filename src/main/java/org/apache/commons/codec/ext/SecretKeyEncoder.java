package org.apache.commons.codec.ext;

import java.security.GeneralSecurityException;
/**
 * 
 * @description:密钥加密算法接口
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-26
 */
public interface SecretKeyEncoder {

	public String encode(String plainText,String key) throws GeneralSecurityException ;
	public String encode(String plainText,byte[] key) throws GeneralSecurityException ;
	public byte[] encode(byte[] plainBytes,String key) throws GeneralSecurityException;
	public byte[] encode(byte[] plainBytes,byte[] key) throws GeneralSecurityException;
	
	
}
