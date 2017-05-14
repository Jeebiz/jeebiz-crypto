package org.apache.commons.codec.ext;

import org.apache.commons.codec.DecoderException;

public interface BinaryDecoder extends org.apache.commons.codec.BinaryDecoder {

	public byte[] decode(byte[] encryptedBytes, int times) throws DecoderException;
	
}
