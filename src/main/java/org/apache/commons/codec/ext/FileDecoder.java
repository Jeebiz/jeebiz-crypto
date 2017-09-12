package org.apache.commons.codec.ext;

import java.io.IOException;
import java.security.GeneralSecurityException;
/**
 * 
 * @description:
 */
public interface FileDecoder {

	public void decode(String key, String encryptedFilePath,String destFilePath) throws GeneralSecurityException,IOException;
	
	public void decode(byte[] key, String encryptedFilePath,String destFilePath) throws GeneralSecurityException,IOException;
	
}
