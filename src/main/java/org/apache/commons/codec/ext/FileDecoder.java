package org.apache.commons.codec.ext;

import java.io.IOException;
import java.security.GeneralSecurityException;
/**
 * 
 * @description:
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-29
 */
public interface FileDecoder {

	public void decode(String key, String encryptedFilePath,String destFilePath) throws GeneralSecurityException,IOException;
	
	public void decode(byte[] key, String encryptedFilePath,String destFilePath) throws GeneralSecurityException,IOException;
	
}
