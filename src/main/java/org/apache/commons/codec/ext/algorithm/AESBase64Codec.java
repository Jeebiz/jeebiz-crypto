package org.apache.commons.codec.ext.algorithm;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

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
 * @description:AES加密解密工具包 AES对称加密算法
 * 				java6实现，bouncycastle也支持AES对称加密算法我们可以以AES算法实现为参考，完成RC2，RC4和Blowfish算法的实现
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-29
 */
public class AESBase64Codec implements Codec, SecretKeyEncoder,SecretKeyDecoder,FileEncoder,FileDecoder {

	
	public byte[] initkey() throws GeneralSecurityException {
		// 初始化密钥生成器，AES要求密钥长度为128位、192位、256位;获取二进制密钥编码形式 ；并进行Base64加密
		return Base64.encodeBase64(SecretKeyUtils.genSecretKey(null,Algorithm.KEY_AES, 256).getEncoded());
	}

	public SecretKey toKey(byte[] base64Key) throws GeneralSecurityException {
		 //实例化AES密钥
		return SecretKeyUtils.genSecretKey(Base64.decodeBase64(base64Key),Algorithm.KEY_AES);
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
	
	/**
	 * 
	 * @description: 加密数据
	 * @author : wandalong
	 * @date : 2014-9-29
	 * @time : 下午6:50:03 
	 * @param plainBytes 待加密数据
	 * @param base64Key  密钥
	 * @return byte[] 加密后的数据
	 * @throws GeneralSecurityException
	 */
	public byte[] encode(byte[] plainBytes, byte[] base64Key) throws GeneralSecurityException {
		//还原密钥
		Key secretKey = toKey(base64Key);
		// 根据秘钥和算法获取加密执行对象；用密钥初始化此 cipher ，设置为加密模式  ;
		/**
		 * 实例化 使用 PKCS7PADDING 填充方式，按如下方式实现,就是调用bouncycastle组件实现
		 * Cipher.getInstance(CIPHER_Algorithm.KEY_AES,"BC")
		 */
		Cipher enCipher = CipherUtils.getEncryptCipher(Algorithm.KEY_CIPHER_AES, secretKey);
		//执行加密操作
		plainBytes = EncryptUtils.encrypt(enCipher, secretKey, plainBytes);
		//使用base64加密算法对DES摘要算法结果进行加密
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
			Cipher enCipher = CipherUtils.getEncryptCipher(Algorithm.KEY_CIPHER_AES, secretKey);
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
	
	/**
	 * 
	 * @description: 解密数据
	 * @author : wandalong
	 * @date : 2014-9-29
	 * @time : 下午6:43:10 
	 * @param data 待解密数据
	 * @param base64Key  密钥
	 * @return byte[] 解密后的数据
	 * @throws GeneralSecurityException
	 */
	public byte[] decode(byte[] encryptedBytes, byte[] base64Key) throws GeneralSecurityException {
		//还原密钥
		Key secretKey = toKey(base64Key);
		// 根据秘钥和算法获取解密执行对象；用密钥初始化此 cipher ，设置为解密模式  ;
		/**
		 * 实例化 使用 PKCS7PADDING 填充方式，按如下方式实现,就是调用bouncycastle组件实现
		 * Cipher.getInstance(CIPHER_Algorithm.KEY_AES,"BC")
		 */
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
			Cipher deCipher = CipherUtils.getDecryptCipher(Algorithm.KEY_CIPHER_AES, secretKey);
			//使用初始化的加密对象对文件进行解密处理
			DecryptUtils.decrypt(deCipher, sourceFile.getAbsolutePath(), destFilePath);
		}
	}
	

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		AESBase64Codec codec = new AESBase64Codec();
		String str = "AES";
		System.out.println("原文：" + str);
		//初始化密钥生成器，AES要求密钥长度为128位、192位、256位
		byte[] base64Key = SecretKeyUtils.genBinarySecretKey(Algorithm.KEY_AES, 256);
		
		
		System.out.println(base64Key.length);
		System.out.println(Base64.encodeBase64(base64Key).length);
		System.out.println("密钥：" + Base64.encodeBase64String(Base64.encodeBase64(base64Key)));
		// 加密数据
		byte[] data = codec.encode(str.getBytes(), Base64.encodeBase64(base64Key));
		System.out.println("加密后：" + Base64.encodeBase64String(data));
		// 解密数据
		data = codec.decode(data, base64Key);
		System.out.println("解密后：" + new String(data));
	}

	

}
