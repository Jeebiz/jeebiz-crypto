package org.apache.commons.codec.ext;

import java.io.IOException;
import java.security.GeneralSecurityException;
/**
 * 
 * @description:
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-29
 */
public interface FileEncoder {

	public void encode(String key, String sourceFilePath,String destFilePath) throws GeneralSecurityException,IOException;
	
	public void encode(byte[] key, String sourceFilePath,String destFilePath) throws GeneralSecurityException,IOException;
	
}
