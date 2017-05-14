package org.apache.commons.codec.ext;

import java.security.GeneralSecurityException;
import java.security.Key;

public interface Codec {
	
	/**
	 * 
	 * @description: 初始化key
	 * @author : wandalong
	 * @date : 2014-9-29
	 * @time : 下午6:21:49 
	 * @return
	 * @throws Exception
	 */
	 public byte[] initkey() throws GeneralSecurityException;
	 
	 /**
	  * 
	  * @description: 还原key
	  * @author : wandalong
	  * @date : 2014-9-29
	  * @time : 下午6:22:02 
	  * @param key
	  * @return
	  * @throws Exception
	  */
	 public Key toKey(byte[] key) throws GeneralSecurityException;
	 
	 public Key toKey(String key) throws GeneralSecurityException;
	 
}
