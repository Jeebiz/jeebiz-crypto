package org.apache.commons.codec.ext.algorithm;

import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringEncoder;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.ext.InputStreamEncoder;
import org.apache.commons.codec.ext.StringVerifier;
import org.apache.commons.codec.ext.digest.DigestUtils;
import org.apache.commons.codec.ext.utils.StringUtils;
/**
 * 
 * @description:bouncy castle扩展支持的MD4的算法实现
 */
public class MD4HexCodec implements StringEncoder,BinaryEncoder,InputStreamEncoder,StringVerifier  {

	private static MD4HexCodec instance = null;
	private MD4HexCodec(){};
	public static MD4HexCodec getInstance(){
		instance= (instance==null)?instance=new MD4HexCodec():instance;
		return  instance;
	}
	
	public Object encode(Object source) throws EncoderException{
		if (source == null) {
            return null;
        } else if (source instanceof String) {
            return encode((String) source);
        } else {
            throw new EncoderException("Objects of type " + source.getClass().getName() + " cannot be encoded using MD4HexCodec");
        }
	}

	public String encode(String source){
		return Hex.encodeHexString(DigestUtils.md4(source.getBytes()));
	}
	
	public String encode(String source, int times){
		String encoded = encode(source);
		for (int i = 0; i < times - 1; i++) {
			encoded = encode(encoded);
		}
		return encoded;
	}
	
	public byte[] encode(byte[] source){
		return StringUtils.getBytesUtf8(Hex.encodeHexString(DigestUtils.md4(source)));
	}
	
	public byte[] encode(byte[] bytes, int times){
		byte[] encoded = encode(bytes);
		for (int i = 0; i < times - 1; i++) {
			encoded = encode(encoded);
		}
		return encoded;
	}
	
	public String encode(InputStream source) throws IOException {
		return Hex.encodeHexString(DigestUtils.md4(source));
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

	
	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		String str="bouncycast 的消息摘要算法";
		System.out.println("原文："+str);
		byte[] data1=  MD4HexCodec.getInstance().encode(str.getBytes());
		System.out.println("MD4的消息摘要算法值："+data1.toString());
		
		String data2= MD4HexCodec.getInstance().encode(str);
		System.out.println("MD4做十六进制编码处理的消息摘要算法值："+data2);
		
		
	}
	
}
