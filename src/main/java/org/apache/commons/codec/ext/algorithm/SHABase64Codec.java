package org.apache.commons.codec.ext.algorithm;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringEncoder;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.ext.InputStreamEncoder;
import org.apache.commons.codec.ext.StringVerifier;
import org.apache.commons.codec.ext.digest.DigestUtils;
import org.apache.commons.codec.ext.utils.StringUtils;

public class SHABase64Codec  implements StringEncoder,BinaryEncoder,InputStreamEncoder,StringVerifier  {
	
	private static SHABase64Codec instance = null;
	private SHABase64Codec(){};
	public static SHABase64Codec getInstance(){
		instance= (instance==null)?instance=new SHABase64Codec():instance;
		return  instance;
	}
	
	private byte[] buffer(byte[] encoded){
		StringBuffer buf  = new StringBuffer();
        for (int i = 0; i < encoded.length; i++) {
            if ((encoded[i] & 0xff) < 0x10) {
                buf.append("0");
            }
            buf.append(Long.toString(encoded[i] & 0xff, 16));
        }
        return StringUtils.getBytesUtf8(buf.toString());
	}
	
	
	public Object encode(Object plainObject) throws EncoderException {
		if (plainObject == null) {
            return null;
        } else if (plainObject instanceof String) {
            return encode((String) plainObject);
        } else {
            throw new EncoderException("Objects of type " + plainObject.getClass().getName() + " cannot be encoded using SHAHexCodec");
        }
	}

	public String encode(String plainText) {
        return Base64.encodeBase64String(buffer(DigestUtils.sha(plainText)) );
	}
	
	/**
	 * 提供一个MD5多次加密方法
	 */
	public String encode(String plainText, int times) throws EncoderException {
		//第一次加密
		byte[] binaryData = buffer(DigestUtils.sha(plainText.getBytes()));
		for (int i = 0; i < times - 1; i++) {
			//多次加密
			binaryData = buffer(DigestUtils.sha(binaryData));
		}
		return Base64.encodeBase64String(binaryData);
	}
	
	/**
	 * 
	 * @description: SHA-256消息摘要
	 * @param plainText
	 * @return
	 * @throws EncoderException
	 */
	public String encodeSHA256(String plainText) throws EncoderException {
        return Base64.encodeBase64String(buffer(DigestUtils.sha256(plainText)) );
	}
	
	public String encodeSHA384(String plainText) throws EncoderException {
        return Base64.encodeBase64String(buffer(DigestUtils.sha384(plainText)) );
	}
	
	public String encodeSHA512(String plainText) throws EncoderException {
        return Base64.encodeBase64String(buffer(DigestUtils.sha512(plainText)) );
	}
	
	public byte[] encode(byte[] plainBytes) {
        return Base64.encodeBase64(buffer(DigestUtils.sha(plainBytes)));
	}
	
	public byte[] encodeSHA256(byte[] plainBytes) throws EncoderException{
		return Base64.encodeBase64(buffer(DigestUtils.sha256(plainBytes)));
	}
	
	public byte[] encodeSHA384(byte[] plainBytes) throws EncoderException{
		return Base64.encodeBase64(buffer(DigestUtils.sha384(plainBytes)));
	}

	public byte[] encodeSHA512(byte[] plainBytes) {
		return Base64.encodeBase64(buffer(DigestUtils.sha512(plainBytes)));
	}
	
	public byte[] encode(byte[] bytes, int times)  {
		//第一次加密
		byte[] binaryData = buffer(DigestUtils.sha(bytes));
		for (int i = 0; i < times - 1; i++) {
			//多次加密
			binaryData = buffer(DigestUtils.sha(binaryData));
		}
		return Base64.encodeBase64(binaryData);
	}
	
	public String encode(InputStream plainStream) throws IOException {
		return Base64.encodeBase64String(buffer(DigestUtils.sha(plainStream)));
	}
	
	public String encodeSHA256(InputStream plainStream) throws IOException{
		return Base64.encodeBase64String(buffer(DigestUtils.sha256(plainStream)));
	}
	
	public String encodeSHA384(InputStream plainStream) throws IOException{
		return Base64.encodeBase64String(buffer(DigestUtils.sha384(plainStream)));
	}

	public String encodeSHA512(InputStream plainStream) throws IOException{
		return Base64.encodeBase64String(buffer(DigestUtils.sha512(plainStream)));
	}
	
	/**
	 * 密码验证方法
	 */
	public boolean verify(String plainText, String encrypt) throws EncoderException {
		return encode(plainText).equals(encrypt);
	}

	/**
	 * 重载一个多次加密时的密码验证方法
	 * @throws EncoderException 
	 */
	public boolean verify(String plainText, String encrypt, int times) throws EncoderException {
		return encode(plainText, times).equals(encrypt);
	}
	
	/**
	 * 提供一个测试的主函数
	 * @throws EncoderException 
	 */
	public static void main(String[] args) throws Exception {
		
		System.out.println(SHABase64Codec.getInstance().encode(new FileInputStream(new File("D://java//java环境变量设置说明.txt"))));;
		
		SHABase64Codec codec = new SHABase64Codec();
		/*try {
			System.out.println(getMD5DigestHex("").toUpperCase());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		System.out.println("test:" + codec.encode("").toUpperCase());
		System.out.println("123:" + codec.encode("123").toUpperCase());
		System.out.println("123456789:" + codec.encode("123456789").toUpperCase());
		System.out.println("sarin:" + codec.encode("sarin").toUpperCase());
		System.out.println("123:" + codec.encode("123", 4).toUpperCase());
	}



}
