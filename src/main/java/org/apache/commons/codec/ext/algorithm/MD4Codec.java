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
import org.apache.commons.codec.ext.enums.Algorithm;
import org.apache.commons.codec.ext.utils.StringUtils;
/**
 * 
 * @description:bouncy castle扩展支持的MD4的算法实现
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-26
 */
public class MD4Codec implements StringEncoder,BinaryEncoder,InputStreamEncoder,StringVerifier  {

	private static MD4Codec instance = null;
	private MD4Codec(){};
	public static MD4Codec getInstance(){
		instance= (instance==null)?instance=new MD4Codec():instance;
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
		return StringUtils.newStringUtf8(DigestUtils.getDigest(Algorithm.KEY_MD4).digest(source.getBytes()));
	}

	public String encode(String source, int times){
		String encoded = encode(source);
		for (int i = 0; i < times - 1; i++) {
			encoded = encode(encoded);
		}
		return encoded;
	}

	public byte[] encode(byte[] source){
		return DigestUtils.getDigest(Algorithm.KEY_MD4).digest(source);
	}

	public byte[] encode(byte[] bytes, int times){
		byte[] encoded = encode(bytes);
		for (int i = 0; i < times - 1; i++) {
			encoded = encode(encoded);
		}
		return encoded;
	}
	
	public String encode(InputStream source) throws IOException {
		return StringUtils.newStringUtf8(DigestUtils.md4(source));
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
		byte[] data1= MD4Codec.getInstance().encode(str.getBytes());
		
		System.out.println("MD4的消息摘要算法值："+data1.toString());
		System.out.println("MD4做十六进制编码处理的消息摘要算法值："+Hex.encodeHexString(data1));
		
		
	}



	
	
}
