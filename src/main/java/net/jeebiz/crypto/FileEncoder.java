package net.jeebiz.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;
/**
 * 
 * 
 */
public interface FileEncoder {

	public void encode(String key, String sourceFilePath,String destFilePath) throws GeneralSecurityException,IOException;
	
	public void encode(byte[] key, String sourceFilePath,String destFilePath) throws GeneralSecurityException,IOException;
	
}
