package org.apache.commons.codec.ext;

import org.apache.commons.codec.EncoderException;

public interface BinaryEncoder extends org.apache.commons.codec.BinaryEncoder{

	public byte[] encode(byte[] plainBytes, int times) throws EncoderException;
	
}
