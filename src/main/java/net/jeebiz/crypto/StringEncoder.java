package net.jeebiz.crypto;

import org.apache.commons.codec.EncoderException;

public interface StringEncoder extends org.apache.commons.codec.StringEncoder {
	
	public String encode(String plainText, int times) throws EncoderException;
	
}
