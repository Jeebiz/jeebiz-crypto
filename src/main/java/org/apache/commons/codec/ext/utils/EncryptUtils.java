package org.apache.commons.codec.ext.utils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.ext.enums.Algorithm;

/**
 * 
 * @description:加密工具类
 */
public class EncryptUtils {
	
	private static final int CACHE_SIZE = 1024;

	public static byte[] encrypt(String algorithm,Key key,String text) throws Exception{
		return EncryptUtils.encrypt(algorithm, key, URLEncoder.encode(text, "UTF-8").getBytes());
	}
	
	/**
	 * 加密数据
	 * @param algorithm 	加密算法
	 * @param key 			密钥
	 * @param plantBytes 	待加密数据
	 * @return byte[] 		加密后的数据
	 * */
	public static byte[] encrypt(String algorithm,Key key,byte[] plantBytes) throws GeneralSecurityException{
		//实例化
		Cipher cipher = CipherUtils.getCipher(algorithm);
		//执行加密操作;得到加密后的字节数组
		return EncryptUtils.encrypt(cipher, key, plantBytes);
	}
	
	public static byte[] encrypt(Cipher cipher,Key key,byte[] plantBytes) throws GeneralSecurityException{
		// 用密钥初始化此 cipher ，设置为加密模式
		cipher.init(Cipher.ENCRYPT_MODE, key);
		//执行加密操作;得到加密后的字节数组
		return cipher.doFinal(plantBytes);
	}

	public static byte[] encrypt(Cipher cipher,byte[] plantBytes, PublicKey publicKey) throws GeneralSecurityException {
		// 用密钥初始化此 cipher ，设置为加密模式
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		//执行加密操作;得到加密后的字节数组
		return cipher.doFinal(plantBytes);
	}
	
	public static String encryptString(Cipher cipher ,Key key,byte[] plantBytes) throws GeneralSecurityException{
		return StringUtils.newStringUtf8(EncryptUtils.encrypt(cipher, key, plantBytes));
	}
	
	public static String encryptString(Cipher cipher ,Key key,String plainText) throws GeneralSecurityException{
		return EncryptUtils.encryptString(cipher, key, plainText.getBytes());
	}
	

	public static byte[] encrypt(Cipher cipher,String plainText, PublicKey publicKey) throws GeneralSecurityException, UnsupportedEncodingException {
		return encrypt(cipher,URLEncoder.encode(plainText, "UTF-8").getBytes(), publicKey);
	}

	public static String encryptHex(Cipher cipher,byte[] plantBytes, PublicKey publicKey) throws GeneralSecurityException {
		return new String(Hex.encodeHex(encrypt(cipher,plantBytes, publicKey)));
	}

	public static String encryptHex(Cipher cipher,String plainText, PublicKey publicKey) throws GeneralSecurityException, UnsupportedEncodingException {
		return new String(Hex.encodeHex(encrypt(cipher,plainText, publicKey)));
	}

	public static String encryptBase64(Cipher cipher,byte[] plantBytes, PublicKey publicKey) throws GeneralSecurityException {
		return new String(Base64.encodeBase64(encrypt(cipher,plantBytes, publicKey)));
	}

	public static String encryptBase64(Cipher cipher,String plainText, PublicKey publicKey) throws GeneralSecurityException, UnsupportedEncodingException {
		return new String(Base64.encodeBase64(encrypt(cipher,plainText, publicKey)));
	}
	
	/**
	 * 
	 * @description: 加密文件
	 * @param algorithm		 算法名称
	 * @param plaintextFile	 未加密过的文件
	 * @param encryptedFile  加密过的文件
	 * @param keyStream      证书
	 * @throws GeneralSecurityException
	 */
	public static void encrypt(String algorithm,InputStream plaintextFile,OutputStream encryptedFile,InputStream keyStream) throws GeneralSecurityException {
		try {
			//还原密钥
			Key secretKey = SecretKeyUtils.readKey(keyStream);
			//实例化
			Cipher cipher = CipherUtils.getCipher(algorithm);
			//初始化，设置为加密模式
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			//执行操作
			EncryptUtils.encrypt(cipher , plaintextFile, encryptedFile);
			//关闭输入输出流
			plaintextFile.close();
			encryptedFile.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public static void encrypt(Cipher cipher,String plaintextFile,String encryptedFile) throws GeneralSecurityException, IOException {
		EncryptUtils.encrypt(cipher,new FileInputStream(plaintextFile),new FileOutputStream(encryptedFile));
	}
	
	public static void encrypt(Cipher cipher,InputStream in, OutputStream out) throws GeneralSecurityException, IOException {
		CipherInputStream cin = new CipherInputStream(in, cipher);
		byte[] cache = new byte[CACHE_SIZE];
		int nRead = 0;
		while ((nRead = cin.read(cache)) != -1) {
			out.write(cache, 0, nRead);
			out.flush();
		}
		out.close();
		cin.close();
		in.close();
		/*int blockSize = cipher.getBlockSize();
		int outputSize = cipher.getOutputSize(blockSize);
		byte[] inBytes = new byte[blockSize];
		byte[] outBytes = new byte[outputSize];
		int inLength = 0;
		boolean more = true;
		while (more) {
			inLength = in.read(inBytes);
			if (inLength == blockSize){
				int outLength = cipher.update(inBytes, 0, blockSize, outBytes);
				out.write(outBytes, 0, outLength);
			}else{
				more = false;
			}
		}
		if (inLength > 0){
			outBytes = cipher.doFinal(inBytes, 0, inLength);
		}else{
			outBytes = cipher.doFinal();
		}
		out.write(outBytes);*/
	}

	public static void main(String[] args) throws Exception {
		
		/*java AESTest -genkey secret.key
		java AESTest -encrypt plaintextFile encryptedFile secret.key
		java AESTest -decrypt encryptedFile decryptedFile secret.key*/
		
		try {
			
			InputStream plaintextFile = new FileInputStream("D:/java环境变量设置说明.txt");
			OutputStream encryptedFileOut = new FileOutputStream("D:/java环境变量设置说明-encrypt.txt");
			
			//对文件进行加密
			EncryptUtils.encrypt(Algorithm.KEY_AES, plaintextFile, encryptedFileOut, new FileInputStream("D:/secret.key"));
			
		}catch (GeneralSecurityException e){
			e.printStackTrace();
		}

	}
	
}
