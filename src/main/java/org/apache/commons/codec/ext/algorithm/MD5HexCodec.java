package org.apache.commons.codec.ext.algorithm;


import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringEncoder;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.ext.InputStreamEncoder;
import org.apache.commons.codec.ext.StringVerifier;
import org.apache.commons.codec.ext.utils.StringUtils;
/**
 * 
 * @description:标准MD5+Hex加密方法，使用java类库的security包的MessageDigest类处理
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-26
 */
public class MD5HexCodec implements StringEncoder,BinaryEncoder,InputStreamEncoder,StringVerifier {
	
	private static MD5HexCodec instance = null;
	private MD5HexCodec(){};
	public static MD5HexCodec getInstance(){
		instance= (instance==null)?instance=new MD5HexCodec():instance;
		return  instance;
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

	@Override
	public Object encode(Object source) throws EncoderException{
		if (source == null) {
            return null;
        } else if (source instanceof String) {
            return encode((String) source);
        } else {
            throw new EncoderException("Objects of type " + source.getClass().getName() + " cannot be encoded using MD5HexCodec");
        }
	}

	@Override
	public byte[] encode(byte[] source){
		return StringUtils.getBytesUtf8(DigestUtils.md5Hex(source));
	}

	@Override
	public String encode(String source){
		return DigestUtils.md5Hex(source);
	}
	
	/**
	 * 提供一个MD5多次加密方法
	 */
	public String encode(String source, int times){
		String encoded = encode(source);
		for (int i = 0; i < times - 1; i++) {
			encoded = encode(encoded);
		}
		return encoded;
	}
	
	public String encode(InputStream source) throws IOException {
		return Hex.encodeHexString(DigestUtils.md5(source));
	}
	
	/**
	 * 提供一个测试的主函数
	 * @throws EncoderException 
	 */
	public static void main(String[] args){
		
		MD5HexCodec md5hex = new MD5HexCodec();
		/*try {
			System.out.println(getMD5DigestHex("").toUpperCase());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		System.out.println("test:" + md5hex.encode("").toUpperCase());
		System.out.println("123:" + md5hex.encode("123").toUpperCase());
		System.out.println("123456789:" + md5hex.encode("123456789").toUpperCase().length());
		System.out.println("sarin:" + md5hex.encode("sarin").toUpperCase().length());
		System.out.println("123:" + md5hex.encode("123", 4).toUpperCase().length());
	}
	
}