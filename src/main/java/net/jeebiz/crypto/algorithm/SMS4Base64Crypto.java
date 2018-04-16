package net.jeebiz.crypto.algorithm;

import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringDecoder;
import org.apache.commons.codec.StringEncoder;
import org.apache.commons.codec.binary.Base64;
import net.jeebiz.crypto.BinaryDecryptor;
import net.jeebiz.crypto.BinaryVerifier;
import net.jeebiz.crypto.StringVerifier;
import net.jeebiz.crypto.utils.StringUtils;

/**
 * 
 * 基于国密SMS4算法的加密解密类
 */
public class SMS4Base64Crypto implements StringEncoder,StringDecoder,BinaryEncoder,BinaryDecryptor,StringVerifier,BinaryVerifier {
	
	private byte[] key;
	private static SMS4Base64Crypto instance = null;
	private SMS4Base64Crypto(byte[] key){
		this.key = key;
	};
	
	public static SMS4Base64Crypto getInstance(byte[] key){
		instance= (instance==null)?instance= new SMS4Base64Crypto(key):instance;
		return  instance;
	}

	public Object encode(Object plainObject) throws EncoderException{
		if (plainObject == null) {
            return null;
        } else if (plainObject instanceof String) {
			return encode((String) plainObject);
        } else {
            throw new EncoderException("Objects of type " + plainObject.getClass().getName() + " cannot be encoded using MD4HexCodec");
        }
	}

	/*public String encode(String plainText) throws EncoderException {
		return Base64.encodeBase64String(SMS4.getInstance().encrypt(plainText.getBytes(), key));
	}
	
	public String encode(String plainText, int times) throws EncoderException {
		//第一次加密
		byte[] binaryData = SMS4.getInstance().encrypt(plainText.getBytes(), key);
		//多次加密
		for (int i = 0; i < times - 1; i++) {
			binaryData = SMS4.getInstance().encrypt(binaryData, key);
		}
		return Base64.encodeBase64String(binaryData);
	}*/
	
	@Override
	public byte[] encode(byte[] plainBytes) throws EncoderException {
		return null;
		//return Base64.encodeBase64(SMS4.getInstance().encrypt(plainBytes, key));
	}
	
	public byte[] encode(byte[] plainBytes, int times) throws EncoderException {
		/*//第一次加密
		byte[] binaryData = SMS4.getInstance().encrypt(plainBytes, key);
		//多次加密
		for (int i = 0; i < times - 1; i++) {
			binaryData = SMS4.getInstance().encrypt(binaryData, key);
		}
		return Base64.encodeBase64(binaryData);*/
		return null;
	}

	@Override
	public Object decode(Object encryptedObject) throws DecoderException {
		if (encryptedObject == null) {
            return null;
        } else if (encryptedObject instanceof String) {
            return decode((String) encryptedObject);
        } else {
            throw new DecoderException("Objects of type " + encryptedObject.getClass().getName() + " cannot be decoded using SMS4Base64Codec");
        }
	}
	
	@Override
	public String decode(String encryptedText) throws DecoderException {
		//return StringUtils.newStringUtf8(SMS4.getInstance().decrypt(Base64.decodeBase64(encryptedText), key));
		return null;
	}
	
	public String decode(String encryptedText, int times) throws DecoderException {
		//第一次解密
		//byte[] binaryData = SMS4.getInstance().decrypt(Base64.decodeBase64(encryptedText), key);;
		//多次解密
		/*for (int i = 0; i < times - 1; i++) {
			binaryData = SMS4.getInstance().decrypt(binaryData, key);
		}*/
		//转换String
		//return StringUtils.newStringUtf8(binaryData);
		return null;
	}

	public byte[] decode(byte[] encryptedBytes) throws DecoderException {
		//return SMS4.getInstance().decrypt(Base64.decodeBase64(encryptedBytes), key);
		return null;
	}

	@Override
	public byte[] decode(byte[] encryptedBytes, int times) throws DecoderException {
		/*//第一次解密
		byte[] binaryData = SMS4.getInstance().decrypt(Base64.decodeBase64(encryptedBytes), key);;
		//多次解密
		for (int i = 0; i < times - 1; i++) {
			binaryData = SMS4.getInstance().decrypt(binaryData, key);
		}
		return binaryData;*/
		return null;
	}
	
	/**
	 * 密码验证方法
	 * @throws EncoderException 
	 */
	public boolean verify(String source, String encrypt) throws EncoderException{
		return encode(source).equals(encrypt);
	}

	/**
	 * 重载一个多次加密时的密码验证方法
	 * @throws EncoderException 
	 */
	public boolean verify(String source, String encrypt, int times) throws EncoderException{
		//return encode(source, times).equals(encrypt);
		return false;
	}

	public boolean verify(byte[] source, byte[] encrypt) throws EncoderException {
		return encode(source).equals(encrypt);
	}
	
	public boolean verify(byte[] source, byte[] encrypt, int times) throws EncoderException {
		return encode(source, times).equals(encrypt);
	}
	
	public String toString(String text) throws EncoderException{
		return "{SMS4Base64}" + encode(text);
	}
	
	public static void main(String[] args) throws Exception {
		
		
		byte[] in =  "4G USIM卡备卡是为您原卡制作的一张备用卡，相比原卡，安全性更高、容量更大、建议您尽快激活、更换使用USIM卡，并剪毁原卡，确保用卡安全。".getBytes();
		
		byte[] key = "300061103172120170".getBytes();
		
		System.out.println("Key：");
		for (int i = 0; i < key.length; i++){
			System.out.print(Integer.toHexString(key[i] & 0xff) + "");
		}
		
		byte[] out = null;
		long starttime;
		System.out.println();
		System.out.println("加密前：" + StringUtils.newStringUtf8(in));
		
		// 加密 128bit
		starttime = System.nanoTime();
		out = SMS4Base64Crypto.getInstance(key).encode(in);
		System.out.println();
		System.out.println("加密1个分组执行时间： " + (System.nanoTime() - starttime) + "ns");
		System.out.println("加密结果：");
		for (int i = 0; i < out.length; i++){
			System.out.print(Integer.toHexString(out[i] & 0xff) + "");
		}
		
		// 解密 128bit
		System.out.println();
		in = SMS4Base64Crypto.getInstance(key).decode(out);
		System.out.println("解密结果："+ StringUtils.newStringUtf8(in));
		
	}

	@Override
	public String encode(String source) throws EncoderException {
		// TODO Auto-generated method stub
		return null;
	}
	
}
