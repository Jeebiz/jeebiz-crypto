package net.jeebiz.crypto.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.DESKeySpec;

import net.jeebiz.crypto.enums.Algorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 * 
 * 加密工具
 */
public final class CipherUtils {
	
	static {
		if(Security.getProvider("BC") == null){
			// 加入bouncyCastle支持
			Security.addProvider(new BouncyCastleProvider());
		}
	}
	
	/**
	 * 
	 *  生成一个实现RSA转换的 Cipher 对象。Cipher对象实际完成加解密操作
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static Cipher getRSACipher() throws GeneralSecurityException {
		return Cipher.getInstance(Algorithm.KEY_CIPHER_RSA);
	}
	
	/**
	 * 
	 *  生成一个实现AES转换的 Cipher 对象。Cipher对象实际完成加解密操作
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static Cipher getAESCipher() throws GeneralSecurityException {
		//生成一个实现AES转换的 Cipher 对象
		return Cipher.getInstance(Algorithm.KEY_CIPHER_AES);
	}
	
	/**
	 * 
	 *  生成一个实现DES转换的 Cipher 对象。Cipher对象实际完成加解密操作
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static Cipher getDESCipher() throws GeneralSecurityException {
		//生成一个实现DES转换的 Cipher 对象
		return Cipher.getInstance(Algorithm.KEY_CIPHER_DES);
	}
	
	/**
	 * 
	 *   加密解密第2步：生成一个实现指定转换的 Cipher 对象。Cipher对象实际完成加解密操作
	 * @param algorithm
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static Cipher getCipher(String algorithm) throws GeneralSecurityException {
		// 返回 cipher
		return  CipherUtils.getCipher(algorithm,null);
	}
	
	public static Cipher getCipher(String algorithm,String provider) throws GeneralSecurityException {
		//生成一个实现转换的 Cipher 对象
		if(null != provider){
			return Cipher.getInstance(algorithm,provider);
		}else{
			return Cipher.getInstance(algorithm);
		}
	}
	
	public static Cipher getEncryptCipher(String algorithm,Key secretKey) throws GeneralSecurityException {
		// 返回 cipher
		return  CipherUtils.getEncryptCipher(algorithm,secretKey,null,null);
	}
	
	public static Cipher getEncryptCipher(String algorithm,Key secretKey,String provider) throws GeneralSecurityException {
		// 返回 cipher
		return  CipherUtils.getEncryptCipher(algorithm,secretKey,null,provider);
	}
	
	public static Cipher getEncryptCipher(String algorithm,Key secretKey,SecureRandom random) throws GeneralSecurityException {
		// 返回 cipher
		return  CipherUtils.getEncryptCipher(algorithm,secretKey,null,null);
	}
	
	public static Cipher getEncryptCipher(String algorithm,Key secretKey,SecureRandom random,String provider) throws GeneralSecurityException {
		//生成一个实现转换的 Cipher 对象
		Cipher cipher = CipherUtils.getCipher(algorithm,provider);
		// 用密钥初始化此 cipher ，设置为解密模式  
		if(null == random){
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);  
		}else{
			cipher.init(Cipher.ENCRYPT_MODE, secretKey , random);  
		}
		// 返回 cipher
		return cipher;
	}
	
	public static Cipher getDecryptCipher(String algorithm,Key secretKey) throws GeneralSecurityException {
		// 返回 cipher
		return  CipherUtils.getDecryptCipher(algorithm,secretKey,null,null);
	}
	
	public static Cipher getDecryptCipher(String algorithm,Key secretKey,String provider) throws GeneralSecurityException {
		// 返回 cipher
		return  CipherUtils.getDecryptCipher(algorithm,secretKey,null,provider);
	}
	
	public static Cipher getDecryptCipher(String algorithm,Key secretKey,SecureRandom random) throws GeneralSecurityException {
		// 返回 cipher
		return  CipherUtils.getDecryptCipher(algorithm,secretKey,null,null);
	}
	
	public static Cipher getDecryptCipher(String algorithm,Key secretKey,SecureRandom random,String provider) throws GeneralSecurityException {
		//生成一个实现RSA转换的 Cipher 对象
		Cipher cipher = CipherUtils.getCipher(algorithm,provider);
		// 用密钥初始化此 cipher ，设置为解密模式  
		if(null == random){
			cipher.init(Cipher.DECRYPT_MODE, secretKey);  
		}else{
			cipher.init(Cipher.DECRYPT_MODE, secretKey , random);  
		}
		// 返回 cipher
		return cipher;
	}
	
	/**
	 * 
	 *  数据分段加密/解密
	 * @param cipher
	 * @param bytes
	 * @param block
	 * @return
	 * @throws GeneralSecurityException
	 * @return  byte[] 返回类型
	 * @throws  
	 * @modify by:
	 * @modify date :
	 * @modify description : TODO(描述修改内容)
	 */
	public static byte[] segment(Cipher cipher,byte[] bytes,int block) throws GeneralSecurityException{
		//分段加密
 	 	int inputLen = bytes.length;  
        ByteArrayOutputStream out = new ByteArrayOutputStream();  
        int offSet = 0;  
        byte[] cache;  
        int i = 0;  
        // 对数据分段加密  
        while (inputLen - offSet > 0) {  
            if (inputLen - offSet > block) {  
                cache = cipher.doFinal(bytes, offSet, block);  
            } else {  
                cache = cipher.doFinal(bytes, offSet, inputLen - offSet);  
            }  
            out.write(cache, 0, cache.length);  
            i++;  
            offSet = i * block;  
        }  
        byte[] binaryData = out.toByteArray();  
        try {
			out.close();
		} catch (IOException e) {
			return null;
		} 
        return binaryData;
	}


	public static void main(String[] args) throws Exception {
		
		try {
			
			SecretKeyUtils.genSecretKey(new DESKeySpec("11111111".getBytes()),Algorithm.KEY_CIPHER_AES);
				
			 
			byte[] key = SecretKeyUtils.genBinarySecretKey(Algorithm.KEY_AES, 56);
			
			CipherUtils.getDecryptCipher(Algorithm.KEY_CIPHER_AES, SecretKeyUtils.genSecretKey(key,Algorithm.KEY_AES));
			
			
		}catch (GeneralSecurityException e){
			e.printStackTrace();
		}

	}

}
