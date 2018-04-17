package net.jeebiz.crypto.algorithm;


import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringEncoder;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import net.jeebiz.crypto.InputStreamEncryptor;
import net.jeebiz.crypto.StringVerifier;
/**
 * 
 * 标准MD5+Base64加密方法，使用java类库的security包的MessageDigest类处理
 */
public class MD5Base64Crypto implements StringEncoder,BinaryEncoder,InputStreamEncryptor,StringVerifier {
	
	private static MD5Base64Crypto instance = null;
	private MD5Base64Crypto(){};
	public static MD5Base64Crypto getInstance(){
		instance= (instance==null)?instance=new MD5Base64Crypto():instance;
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
            throw new EncoderException("Objects of type " + source.getClass().getName() + " cannot be encoded using MD5Codec");
        }
	}

	@Override
	public byte[] encode(byte[] source){
		return Base64.encodeBase64(DigestUtils.md5(source));
	}

	@Override
	public String encode(String source){
		return Base64.encodeBase64String(DigestUtils.md5(source));
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
		return Base64.encodeBase64String(DigestUtils.md5(source));
	}
	
	
	/**
	 * 提供一个测试的主函数
	 * @throws EncoderException 
	 */
	public static void main(String[] args) throws Exception {
		
		MD5Base64Crypto md5Base64 = new MD5Base64Crypto();
		/*try {
			System.out.println(getMD5DigestHex("").toUpperCase());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		System.out.println("test-encode:" + md5Base64.encode("").toUpperCase().length());
		System.out.println("123-encode:" + md5Base64.encode("123").toUpperCase().length());
		
		System.out.println("123456789-encode:" + md5Base64.encode("123dddddddddddddd456789").toUpperCase().length());
		System.out.println("sarin-encode:" + md5Base64.encode("sarin").toUpperCase());
		System.out.println("123-encode:" + md5Base64.encode("123", 4).toUpperCase());
	}

	
	
}
