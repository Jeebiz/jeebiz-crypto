package org.apache.commons.codec.ext;

import org.apache.commons.codec.EncoderException;

/**
 * 
 * @description:二级制验证
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-26
 */
public interface BinaryVerifier {
	
	public boolean verify(byte[] plantBytes,byte[] encrypt) throws EncoderException;
	
	public boolean verify(byte[] plantBytes,byte[] encrypt, int times) throws EncoderException;
	
}
