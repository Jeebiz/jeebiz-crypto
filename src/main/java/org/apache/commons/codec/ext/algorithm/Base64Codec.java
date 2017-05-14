package org.apache.commons.codec.ext.algorithm;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.ext.BinaryDecoder;
import org.apache.commons.codec.ext.BinaryEncoder;
import org.apache.commons.codec.ext.BinaryVerifier;
import org.apache.commons.codec.ext.StringDecoder;
import org.apache.commons.codec.ext.StringEncoder;
import org.apache.commons.codec.ext.StringVerifier;
import org.apache.commons.codec.ext.utils.StringUtils;
/**
 * 
 * @description:基于apache codec 的base64加密解密实现的扩展
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-26
 */
public class Base64Codec implements StringEncoder,StringDecoder,BinaryEncoder,BinaryDecoder,StringVerifier,BinaryVerifier {
	
	private static Base64Codec instance = null;
	private Base64Codec(){};
	public static Base64Codec getInstance(){
		instance= (instance==null)?instance=new Base64Codec():instance;
		return  instance;
	}
	
	public Object encode(Object source) throws EncoderException{
		if (source == null) {
            return null;
        } else if (source instanceof String) {
            return encode((String) source);
        } else {
            throw new EncoderException("Objects of type " + source.getClass().getName() + " cannot be encoded using Base64Codec");
        }
	}
	
	public String encode(String source){
		return Base64.encodeBase64String(source.getBytes());
	}
	
	
	public String encode(String source, int times){
		String encoded = encode(source);
		for (int i = 0; i < times - 1; i++) {
			encoded = encode(encoded);
		}
		return encoded;
	}
	
	
	public byte[] encode(byte[] source){
		return Base64.encodeBase64(source);
	}
	
	public byte[] encode(byte[] bytes, int times){
		byte[] encoded = encode(bytes);
		for (int i = 0; i < times - 1; i++) {
			encoded = encode(encoded);
		}
		return encoded;
	}
	
	public Object decode(Object source) throws DecoderException {
		if (source == null) {
            return null;
        } else if (source instanceof String) {
            return decode((String) source);
        } else {
            throw new DecoderException("Objects of type " + source.getClass().getName() + " cannot be decoded using Base64Codec");
        }
	}
	
	public String decode(String source) throws DecoderException {
		return StringUtils.newStringUtf8(Base64.decodeBase64(source));
	}
	
	public String decode(String source, int times) throws DecoderException {
		String encoded = decode(source);
		for (int i = 0; i < times - 1; i++) {
			encoded = decode(encoded);
		}
		return encoded;
	}
	
	public byte[] decode(byte[] base64Bytes) throws DecoderException {
		return Base64.decodeBase64(base64Bytes);
	}
	
	public byte[] decode(byte[] base64Bytes, int times) throws DecoderException {
		byte[] encoded = decode(base64Bytes);
		for (int i = 0; i < times - 1; i++) {
			encoded = decode(encoded);
		}
		return encoded;
	}
	
	/**
	 * 密码验证方法
	 */
	public boolean verify(String source, String encrypt){
		return encode(source).equals(encrypt);
	}

	/**
	 * 重载一个多次加密时的密码验证方法
	 * @throws EncoderException 
	 */
	public boolean verify(String source, String encrypt, int times){
		return encode(source, times).equals(encrypt);
	}
	
	
	public boolean verify(byte[] source, byte[] encrypt) throws EncoderException {
		// TODO Auto-generated method stub
		return false;
	}
	
	public boolean verify(byte[] source, byte[] encrypt, int times)
			throws EncoderException {
		// TODO Auto-generated method stub
		return false;
	}
	
	public String toString(String text) throws EncoderException{
		return "{Base64}" + encode(text);
	}
	
	public static void main(String[] args) throws Exception{
		
		String str2 = "jwglxt/jxjh/xqzxjh/xqzxjhcj/XqzxjhrwBjck.jsp";
		String str = Base64Codec.getInstance().encode(str2,2);
		System.out.println(str);
		System.out.println(Base64Codec.getInstance().decode(str,2));
		System.out.println();
		System.out.println(Base64.encodeBase64String(str2.getBytes()));
		System.out.println(StringUtils.newStringUtf8(Base64.decodeBase64(Base64.encodeBase64String(str2.getBytes()))));
	
		System.out.println(Base64Codec.getInstance().toString(str2));
	}
	
}
