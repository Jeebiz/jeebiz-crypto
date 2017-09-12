package org.apache.commons.codec.ext;

import java.security.GeneralSecurityException;
import java.security.Key;

public interface Codec {
	
	/**
	 * 
	 * @description: 初始化key
	 * @return
	 * @throws Exception
	 */
	 public byte[] initkey() throws GeneralSecurityException;
	 
	 /**
	  * 
	  * @description: 还原key
	  * @param key
	  * @return
	  * @throws Exception
	  */
	 public Key toKey(byte[] key) throws GeneralSecurityException;
	 
	 public Key toKey(String key) throws GeneralSecurityException;
	 
}
