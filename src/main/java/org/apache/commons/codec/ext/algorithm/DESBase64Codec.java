package org.apache.commons.codec.ext.algorithm;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.ext.Codec;
import org.apache.commons.codec.ext.FileDecoder;
import org.apache.commons.codec.ext.FileEncoder;
import org.apache.commons.codec.ext.SecretKeyDecoder;
import org.apache.commons.codec.ext.SecretKeyEncoder;
import org.apache.commons.codec.ext.enums.Algorithm;
import org.apache.commons.codec.ext.utils.CipherUtils;
import org.apache.commons.codec.ext.utils.DecryptUtils;
import org.apache.commons.codec.ext.utils.EncryptUtils;
import org.apache.commons.codec.ext.utils.SecretKeyUtils;
import org.apache.commons.codec.ext.utils.StringUtils;
/**
 * 
 * @package org.apache.commons.codec.ext.algorithm
 * @className: DESCodec
 * @description: DES对称加密算法
 */
public class DESBase64Codec implements Codec,SecretKeyEncoder,SecretKeyDecoder,FileEncoder,FileDecoder {
	
	
	private static DESBase64Codec instance = null;
	private DESBase64Codec(){};
	public static DESBase64Codec getInstance(){
		instance= (instance==null)?instance=new DESBase64Codec():instance;
		return  instance;
	}
	
	public byte[] initkey() throws GeneralSecurityException {
        //获取二进制密钥编码形式  ；并进行Base64加密
        return Base64.encodeBase64(SecretKeyUtils.genSecretKey(null,Algorithm.KEY_DES, 56).getEncoded()); 
	}
	
	public Key toKey(byte[] base64Key) throws GeneralSecurityException {
		return SecretKeyUtils.genDESKey(Base64.decodeBase64(base64Key));
	}
	
	public Key toKey(String key) throws GeneralSecurityException{
		return toKey(key.getBytes());
	}
	
	public String encode(String plainText, String base64Key) throws GeneralSecurityException {
		return encode(plainText, base64Key.getBytes());
	}
	
	public String encode(String plainText, byte[] base64Key) throws GeneralSecurityException {
		return StringUtils.newStringUtf8(encode(plainText.getBytes(),base64Key));
	}
	
	public byte[] encode(byte[] plainBytes, String base64Key) throws GeneralSecurityException {
		return encode(plainBytes, base64Key.getBytes());
	}

	public byte[] encode(byte[] plainBytes, byte[] base64Key) throws GeneralSecurityException {
		//还原密钥
		Key secretKey = toKey(base64Key);
		// 根据秘钥和算法获取加密执行对象；用密钥初始化此 cipher ，设置为加密模式  ;
		Cipher enCipher = CipherUtils.getEncryptCipher(Algorithm.KEY_CIPHER_DES, secretKey);
		//执行加密操作
		plainBytes = EncryptUtils.encrypt(enCipher, secretKey, plainBytes);
		/*使用base64加密算法对DES摘要算法结果进行加密
		   1、为了防止解密时报javax.crypto.IllegalBlockSizeException: Input length must be multiple of 8 when decrypting with padded cipher异常，  
           2、不能把加密后的字节数组直接转换成字符串  
		*/
		return Base64.encodeBase64(plainBytes);
	}
	
	public void encode(String key, String sourceFilePath, String destFilePath) throws GeneralSecurityException, IOException {
		encode(key.getBytes(), sourceFilePath,destFilePath);
	}

	public void encode(byte[] base64Key, String sourceFilePath, String destFilePath) throws GeneralSecurityException, IOException {
		File sourceFile = new File(sourceFilePath);
		if (sourceFile.exists() && sourceFile.isFile()) {
			//还原密钥
			Key secretKey = toKey(base64Key);
			// 根据秘钥和算法获取加密执行对象；用密钥初始化此 cipher ，设置为加密模式  ;
			Cipher enCipher = CipherUtils.getEncryptCipher(Algorithm.KEY_CIPHER_DES, secretKey);
			//使用初始化的加密对象对文件进行加密处理
			EncryptUtils.encrypt(enCipher, sourceFile.getAbsolutePath(), destFilePath);
		}
	}
	
	public String decode(String encryptedText, String base64Key) throws GeneralSecurityException {
		return decode(encryptedText, base64Key.getBytes());
	}
	
	public String decode(String encryptedText, byte[] base64Key) throws GeneralSecurityException {
		return StringUtils.newStringUtf8(decode(encryptedText.getBytes(), base64Key));
	}
	
	public byte[] decode(byte[] encryptedBytes, String base64Key) throws GeneralSecurityException {
		return decode(encryptedBytes, base64Key.getBytes());
	}
	
	public byte[] decode(byte[] encryptedBytes, byte[] base64Key) throws GeneralSecurityException {
		//还原密钥
		Key secretKey = toKey(base64Key);
		// 根据秘钥和算法获取解密执行对象；用密钥初始化此 cipher ，设置为解密模式  ;
		Cipher deCipher = CipherUtils.getDecryptCipher(Algorithm.KEY_CIPHER_DES, secretKey);
		//使用base64加密算法对base64Bytes数组解密；
		encryptedBytes = Base64.decodeBase64(encryptedBytes);
		//DES摘要算法对base64解密后的结果进行解密
		return DecryptUtils.decrypt(deCipher, secretKey , encryptedBytes);
	}
	
	public void decode(String key, String encryptedFilePath, String destFilePath) throws GeneralSecurityException, IOException {
		decode(key.getBytes(), encryptedFilePath,destFilePath);
	}

	public void decode(byte[] base64Key, String encryptedFilePath, String destFilePath) throws GeneralSecurityException, IOException {
		File sourceFile = new File(encryptedFilePath);
		if (sourceFile.exists() && sourceFile.isFile()) {
			//还原密钥
			Key secretKey = toKey(base64Key);
			// 根据秘钥和算法获取加密执行对象；用密钥初始化此 cipher ，设置为解密模式  ;
			Cipher deCipher = CipherUtils.getDecryptCipher(Algorithm.KEY_CIPHER_DES, secretKey);
			//使用初始化的加密对象对文件进行解密处理
			DecryptUtils.decrypt(deCipher, sourceFile.getAbsolutePath(), destFilePath);
		}
	}
	
	public static void main(String[] args) throws Exception {
		
		String str="DES";
		
		String encryptKey = StringUtils.newStringUtf8(DESBase64Codec.getInstance().initkey());
		
		System.out.println("原文："+str); 
		System.out.println("密钥："+ encryptKey);
		//加密数据
		String encryptedText = DESBase64Codec.getInstance().encode(str, encryptKey);
		System.out.println("加密后："+encryptedText);
		//解密数据
		System.out.println("解密后："+ DESBase64Codec.getInstance().decode(encryptedText, encryptKey));

		/*<property name="jdbcUrl" value=></property> 
        <property name="user" value=></property>
        <property name="password" value=></property>
        	服务器：10.71.32.37  SID:test    用户名：zftal_jwcj   密码：zftal_jwcj
        */
		String encryptKeyText = "7EV/Zzutjzg=";
		
		//"jdbc:oracle:thin:@10.71.32.37:1521:DevDB";  / szzyjwa
		String jdbcUrlText = "jdbc:oracle:thin:@10.71.32.37:1521:test";
		String userText = "zftal_jwcj";
		String passwordText = "zftal_jwcj";
		
		String jdbcUrl = DESBase64Codec.getInstance().encode(jdbcUrlText,encryptKeyText);
		String user = DESBase64Codec.getInstance().encode(userText,encryptKeyText);
		String password =  DESBase64Codec.getInstance().encode(passwordText,encryptKeyText);
		
		System.out.println("jdbcUrlText加密后：" + jdbcUrl);
		System.out.println("userText加密后：" + user);
		System.out.println("passwordText加密后：" +password);
		
    	System.out.println("jdbcUrl解密后：" + DESBase64Codec.getInstance().decode(jdbcUrl,encryptKeyText));
    	System.out.println("user解密后：" + DESBase64Codec.getInstance().decode(user,encryptKeyText));
    	System.out.println("password解密后：" + DESBase64Codec.getInstance().decode(password,encryptKeyText));
    	
    }
	

	
}
