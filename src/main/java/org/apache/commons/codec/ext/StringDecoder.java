package org.apache.commons.codec.ext;

import org.apache.commons.codec.DecoderException;

public interface StringDecoder extends org.apache.commons.codec.StringDecoder{

	public String decode(String encryptedText, int times) throws DecoderException;
	
}
