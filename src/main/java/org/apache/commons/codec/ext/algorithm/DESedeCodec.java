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
 * @className: DESedeCodec
 * @description: DESede对称加密算法
 * @author : wandalong
 * @date : 2014-9-28
 * @time : 下午7:38:13
 */
public class DESedeCodec implements Codec,SecretKeyEncoder,SecretKeyDecoder,FileEncoder,FileDecoder{
	
	private static DESedeCodec instance = null;
	private DESedeCodec(){};
	public static DESedeCodec getInstance(){
		instance= (instance==null)?instance=new DESedeCodec():instance;
		return  instance;
	}
	
	public byte[] initkey() throws GeneralSecurityException {
        //获取二进制密钥编码形式  ；并进行Base64加密
        return Base64.encodeBase64(SecretKeyUtils.genSecretKey(null,Algorithm.KEY_DESEDE, 168).getEncoded()); 
	}
	
	public Key toKey(byte[] base64Key) throws GeneralSecurityException {
		return SecretKeyUtils.genDESedeKey(Base64.decodeBase64(base64Key));
	}
	
	public Key toKey(String key) throws GeneralSecurityException{
		return toKey(key.getBytes());
	}
	
	public String encode(String plainText, String base64Key) throws GeneralSecurityException {
		return encode(plainText, base64Key.getBytes());
	}
	
	public String encode(String plainText, byte[] base64Key) throws GeneralSecurityException {
		return StringUtils.newStringUtf8(encode(plainText.getBytes(), base64Key));
	}
	
	public byte[] encode(byte[] plainBytes, String base64Key) throws GeneralSecurityException {
		return encode(plainBytes, base64Key.getBytes());
	}
	
	public byte[] encode(byte[] plainBytes, byte[] base64Key) throws GeneralSecurityException {
		//还原密钥
		Key k = toKey(base64Key);
		return EncryptUtils.encrypt(CipherUtils.getCipher(Algorithm.KEY_CIPHER_DESEDE), k, plainBytes);
	}
	
	public void encode(String base64Key, String sourceFilePath, String destFilePath) throws GeneralSecurityException, IOException {
		encode(base64Key.getBytes(), sourceFilePath,destFilePath);
	}

	public void encode(byte[] base64Key, String sourceFilePath, String destFilePath) throws GeneralSecurityException, IOException {
		File sourceFile = new File(sourceFilePath);
		if (sourceFile.exists() && sourceFile.isFile()) {
			//还原密钥
			Key secretKey = toKey(base64Key);
			// 根据秘钥和算法获取加密执行对象；用密钥初始化此 cipher ，设置为加密模式  ;
			Cipher enCipher = CipherUtils.getEncryptCipher(Algorithm.KEY_CIPHER_DESEDE, secretKey);
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
		Key k = toKey(base64Key);
		return DecryptUtils.decrypt(CipherUtils.getCipher(Algorithm.KEY_CIPHER_DESEDE), k, encryptedBytes);
	}
	
	public void decode(String base64Key, String encryptedFilePath, String destFilePath) throws GeneralSecurityException, IOException {
		decode(base64Key.getBytes(), encryptedFilePath,destFilePath);
	}

	public void decode(byte[] base64Key, String encryptedFilePath, String destFilePath) throws GeneralSecurityException, IOException {
		File sourceFile = new File(encryptedFilePath);
		if (sourceFile.exists() && sourceFile.isFile()) {
			//还原密钥
			Key secretKey = toKey(base64Key);
			// 根据秘钥和算法获取加密执行对象；用密钥初始化此 cipher ，设置为解密模式  ;
			Cipher deCipher = CipherUtils.getDecryptCipher(Algorithm.KEY_CIPHER_DESEDE, secretKey);
			//使用初始化的加密对象对文件进行解密处理
			DecryptUtils.decrypt(deCipher, sourceFile.getAbsolutePath(), destFilePath);
		}
	}
	
	
	/**
	 * 进行加解密的测试
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		
		String str="DESede";
		System.out.println("原文：/t"+str);
		//获得128位密钥
		byte[] base64Key = SecretKeyUtils.genBinarySecretKey(Algorithm.KEY_DESEDE, 168);
		System.out.println("密钥：/t"+Base64.encodeBase64String(base64Key));
		//加密数据
		byte[] data= DESedeCodec.getInstance().encode(str.getBytes(), Base64.encodeBase64String(base64Key));
		System.out.println("加密后：/t"+Base64.encodeBase64String(data));
		//解密数据
		data= DESedeCodec.getInstance().decode(data, Base64.encodeBase64String(base64Key));
		System.out.println("解密后：/t"+new String(data));
	}
	
}
