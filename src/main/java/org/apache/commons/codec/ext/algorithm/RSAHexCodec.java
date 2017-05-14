 package org.apache.commons.codec.ext.algorithm;
 import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Cipher;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.ext.KeyPairCodec;
import org.apache.commons.codec.ext.KeyPairDecoder;
import org.apache.commons.codec.ext.KeyPairEncoder;
import org.apache.commons.codec.ext.KeyPairVerifier;
import org.apache.commons.codec.ext.enums.Algorithm;
import org.apache.commons.codec.ext.utils.CipherUtils;
import org.apache.commons.codec.ext.utils.SecretKeyUtils;
import org.apache.commons.codec.ext.utils.SignatureUtils;
import org.apache.commons.codec.ext.utils.StringUtils;


 /**
  * 
  * @className: RSACodec
  * @description: RSA安全编码组件
  * @author : wandalong
  * @date : 下午2:35:41 2014-10-9
  * @modify by:
  * @modify date :
  * @modify description :
  */
 public class RSAHexCodec implements KeyPairCodec,KeyPairEncoder,KeyPairDecoder,KeyPairVerifier {

   /**
     * RSA最大加密明文大小 
     */  
    private static final int MAX_ENCRYPT_BLOCK = 117;  
      
    /**
     * RSA最大解密密文大小 
     */  
    private static final int MAX_DECRYPT_BLOCK = 128;  
    
	public final static String public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/2b8sCE3AwdUMgSZWDH4npAyBX3fyI47GU2hQ"
			+ "OwOwlKhGTPixKwGldi/Nx8y/VCoFkXIprcJVHSgq4NDwAGVPUQASjcZrHfVvJ38mc/ZRagkN6zFL"
			+ "iJVEgKwAfgQuK5nsBgdtnfHaXS8C1ZC91bbEooFpKxbzBUSwCsKnHEmS2wIDAQAB";

	public final static  String private_key = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL/ZvywITcDB1QyBJlYMfiekDIFf"
			+ "d/IjjsZTaFA7A7CUqEZM+LErAaV2L83HzL9UKgWRcimtwlUdKCrg0PAAZU9RABKNxmsd9W8nfyZz"
			+ "9lFqCQ3rMUuIlUSArAB+BC4rmewGB22d8dpdLwLVkL3VtsSigWkrFvMFRLAKwqccSZLbAgMBAAEC"
			+ "gYEAp4Jx/vpJGVKkuMRTOrKxu97q5FL9IbiWQug0nkjI0fcabjdqtRZ924C0AJLBXRUZk78I1QdY"
			+ "NIS+u6GMDOHrkbBSnJFdHeMR4PHDFF5Ucrzl6c7nBpgq+ol0FB4HgJTynJGlcO2FvNsUdI4jWZHH"
			+ "zXKmZLKODsoWXQ8COYIWGGECQQDkf25k2LrLXSXAh1bpdIX5SVMXyOAJu2Slm/CNMgUuIX1Y0mcs"
			+ "dqtAcwGGSagKPllBULepW1BCp4gVwwdKM/HDAkEA1vEgaA4lJErDvErTdnXxeskF7/S6xmFR9m5D"
			+ "vOibX9N+ih+es05GOGK1qfiWzihQohsWfDfE1QFInBJLr1VxCQJAeVswz4DIHLA5F7sJru4DJbYK"
			+ "2qwGSUTsnIRoyyTQ2YJR53W/9D6Gj7FFEwRVqjMZBnaPRPRJeU0vGpe9bGyQLwJAHNn/DJihea6j"
			+ "eXndyq/oOyASsPP7wjc8BkUkyI28lW9RM/8skUr3eAgf9HHO5Fta/3d9XC0sOZ9TfMej6yQf6QJA"
			+ "ZE4oQb4hR/dAt80K4vug8Jugbmfg3NXqdU+V0mYVPsC7vao5YlIjnaArrl3WKGZYqrdbuLBYBbcC"
			+ "hOAuyuXtlg==";
	
 	private static RSAHexCodec instance = null;
	private RSAHexCodec(){};
	public static RSAHexCodec getInstance(){
		instance= (instance==null)?instance=new RSAHexCodec():instance;
		return  instance;
	}
	
 	/**
 	 * 初始化密钥
 	 * 
 	 * @return
 	 * @throws Exception
 	 */
	@Override
 	public KeyPair initKey() throws GeneralSecurityException {
 		return this.initKey(512);
 	}
 	
 	public KeyPair initKey(int keysize) throws GeneralSecurityException{
 		return SecretKeyUtils.genKeyPair(Algorithm.KEY_RSA,keysize);
 	}
 	
 	public KeyPairEntry initKeyEntry() throws GeneralSecurityException {
 		return this.initKeyEntry(512);
 	}
 	
 	class DefaultKeyPairEntry implements KeyPairEntry{
 		
 		KeyPair keyPair = null;
 		private DefaultKeyPairEntry(KeyPair keyPair){
 			this.keyPair = keyPair;
 		}
 		
 		public String getPublicKey() {
			return Base64.encodeBase64String(keyPair.getPublic().getEncoded());
		}
		
		public PublicKey getPublic() {
			return keyPair.getPublic();
		}
		
		public String getPrivateKey() {
			return Base64.encodeBase64String(keyPair.getPrivate().getEncoded());
		}
		
		public PrivateKey getPrivate() {
			return keyPair.getPrivate();
		}
 	}
 	
 	public KeyPairEntry initKeyEntry(final int keysize) throws GeneralSecurityException{
 		KeyPair keyPair = SecretKeyUtils.genKeyPair(Algorithm.KEY_RSA,keysize);
 		return new DefaultKeyPairEntry(keyPair);
 	}
 	
 	@Override
	public PublicKey toPublicKey(String base64PublicKeyText) throws GeneralSecurityException {
 		return this.toPublicKey(base64PublicKeyText.getBytes());
	}

 	@Override
	public PublicKey toPublicKey(byte[] base64PublicKeyBytes) throws GeneralSecurityException {
 		// 解密公钥
 		byte[] pubkey_bytes = Base64.decodeBase64(base64PublicKeyBytes);
 		// 取公钥匙对象
 		return SecretKeyUtils.genPublicKey(pubkey_bytes, Algorithm.KEY_RSA);
	}

	@Override
	public PrivateKey toPrivateKey(String base64PrivateKeyText) throws GeneralSecurityException {
		return this.toPrivateKey(base64PrivateKeyText.getBytes());
	}
	
	@Override
	public PrivateKey toPrivateKey(byte[] base64PrivateKeyBytes) throws GeneralSecurityException {
		// 解密私钥
 		byte[] prikey_bytes = Base64.decodeBase64(base64PrivateKeyBytes);
 		// 取私钥匙对象
 	 	return SecretKeyUtils.genPrivateKey(prikey_bytes, Algorithm.KEY_RSA);
	}
	
 	
 	/**
 	 * 用私钥对信息生成数字签名
 	 * 
 	 * @param plainBytes 加密数据
 	 * @param base64PrivateKeyText  私钥
 	 * 
 	 * @return
 	 * @throws Exception
 	 */
 	public String sign(byte[] encryptedBytes, String base64PrivateKeyText) throws GeneralSecurityException {
 		// 取私钥匙对象
 		PrivateKey privateKey =  toPrivateKey(base64PrivateKeyText);
 		//获取签名对象
 		Signature signature = SignatureUtils.getSignature(Algorithm.KEY_SIGNATURE_RSA);
 		//用私钥对信息生成数字签名
 		try {
			return Hex.encodeHexString(SignatureUtils.sign(Hex.decodeHex(new String(encryptedBytes).toCharArray()), signature, privateKey));
		} catch (DecoderException e) {
			e.printStackTrace();
			return null;
		}
 	}


 	/**
 	 * 
 	 * @description:  校验数字签名
 	 * @author : wandalong
 	 * @date 下午1:42:32 2014-10-9 
 	 * @param encryptedBytes 加密数据
 	 * @param base64PublicKeyText 公钥
 	 * @param sign 数字签名
 	 * @return
 	 * @throws Exception
 	 * @return  boolean  校验成功返回true 失败返回false
 	 * @throws  
 	 * @modify by:
 	 * @modify date :
 	 * @modify description : 
 	 */
 	public boolean verify(byte[] encryptedBytes, String base64PublicKeyText, String sign) throws GeneralSecurityException {
 		return verify(encryptedBytes,base64PublicKeyText.getBytes(),sign);
 	}
 	
 	public boolean verify(byte[] encryptedBytes, byte[] base64PublicKeyText, String sign) throws GeneralSecurityException {
 		// 取公钥匙对象
 		PublicKey publicKey = toPublicKey(base64PublicKeyText);
 		//获取签名对象
 		Signature signature = SignatureUtils.getSignature(Algorithm.KEY_SIGNATURE_RSA);
 		try {
			// 验证签名是否正常
			return SignatureUtils.verify(Hex.decodeHex(new String(encryptedBytes).toCharArray()), Hex.decodeHex(sign.toCharArray()), signature, publicKey);
		} catch (DecoderException e) {
			e.printStackTrace();
			return false;
		}
 	}

 	/**
 	 * 解密<br>
 	 * 用私钥解密
 	 * 
 	 * @param plainBytes
 	 * @param key
 	 * @return
 	 * @throws Exception
 	 */
 	@Override
	public String decodeByPrivateKey(String encryptedText, String base64PrivateKeyText) throws GeneralSecurityException {
 		// 取得私钥
		PrivateKey privateKey =  toPrivateKey(base64PrivateKeyText);
		//使用私钥解密
		return this.decode(encryptedText, privateKey);
	}
 	
	@Override
	public String decode(String encryptedText, PrivateKey privateKey) throws GeneralSecurityException {
		// 对数据加密
		return StringUtils.newStringUtf8(this.decode(encryptedText.getBytes(), privateKey));
	}
	
 	@Override
	public byte[] decodeByPrivateKey(byte[] encryptedBytes, String base64PrivateKeyText) throws GeneralSecurityException {
		// 取得私钥
		PrivateKey privateKey =  toPrivateKey(base64PrivateKeyText);
		//使用私钥解密
		return this.decode(encryptedBytes, privateKey);
	}
 	
	@Override
	public byte[] decode(byte[] encryptedBytes, PrivateKey privateKey) throws GeneralSecurityException {
		// 取得Cipher对象
 		Cipher cipher = CipherUtils.getDecryptCipher(Algorithm.KEY_RSA, privateKey);
 		try {
			// 对数据Hex解密
			encryptedBytes = Hex.decodeHex(new String(encryptedBytes).toCharArray());
			// 对数据分段解密  
			return CipherUtils.segment(cipher, encryptedBytes, MAX_DECRYPT_BLOCK);
		} catch (DecoderException e) {
			e.printStackTrace();
			return null;
		}
	}
	

 	/**
 	 * 解密<br>
 	 * 用公钥解密
 	 * 
 	 * @param plainBytes
 	 * @param key
 	 * @return
 	 * @throws Exception
 	 */
	@Override
	public String decodeByPublicKey(String encryptedText, String base64PublicKeyText) throws GeneralSecurityException {
		// 取得公钥
 		PublicKey publicKey = toPublicKey(base64PublicKeyText);
 		//使用公钥解密
 		return this.decode(encryptedText, publicKey);
	}
	
	@Override
	public String decode(String encryptedText, PublicKey publicKey) throws GeneralSecurityException {
		// 对数据加密
		return StringUtils.newStringUtf8(this.decode(encryptedText.getBytes(), publicKey));
	}
	
 	@Override
	public byte[] decodeByPublicKey(byte[] encryptedBytes, String base64PublicKeyText) throws GeneralSecurityException{
 		// 取得公钥
 		PublicKey publicKey = toPublicKey(base64PublicKeyText);
 		//使用公钥解密
 		return this.decode(encryptedBytes, publicKey);
 	}
 
 	@Override
	public byte[] decode(byte[] encryptedBytes, PublicKey publicKey) throws GeneralSecurityException {
 		// 取得Cipher对象
 		Cipher cipher = CipherUtils.getDecryptCipher(Algorithm.KEY_RSA, publicKey);
 		try {
			// 对数据Hex解密
			encryptedBytes = Hex.decodeHex(new String(encryptedBytes).toCharArray());
			// 对数据分段解密  
			return CipherUtils.segment(cipher, encryptedBytes, MAX_DECRYPT_BLOCK);
 		} catch (DecoderException e) {
			e.printStackTrace();
			return null;
		}
	}
 	
 	/**
 	 * 加密<br>
 	 * 用公钥加密
 	 * 
 	 * @param plainBytes
 	 * @param key
 	 * @return
 	 * @throws GeneralSecurityException 
 	 * @throws Exception
 	 */
 	@Override
	public String encodeByPublicKey(String plainText, String base64PublicKeyText) throws GeneralSecurityException {
 		// 取得公钥
 		PublicKey publicKey = toPublicKey(base64PublicKeyText);
 		// 对数据加密
 		return this.encode(plainText, publicKey);
	}
 	
	@Override
	public String encode(String plainText, PublicKey publicKey) throws GeneralSecurityException {
		// 对数据加密
		return StringUtils.newStringUtf8(this.encode(plainText.getBytes(), publicKey));
	}
	
 	public byte[] encodeByPublicKey(byte[] plainBytes, String base64PublicKeyText) throws GeneralSecurityException{
 		// 取得公钥
 		PublicKey publicKey = toPublicKey(base64PublicKeyText);
 		// 对数据加密
 		return this.encode(plainBytes, publicKey);
 	}

	public byte[] encode(byte[] plainBytes, PublicKey publicKey) throws GeneralSecurityException{
 		// 取得Cipher对象
 	 	Cipher cipher = CipherUtils.getEncryptCipher(Algorithm.KEY_RSA, publicKey);
 	 	// 对数据分段加密  
		byte[] encryptedData = CipherUtils.segment(cipher, plainBytes, MAX_ENCRYPT_BLOCK);
		// 对数据加密
 	 	return new String(Hex.encodeHex(encryptedData)).getBytes();
 	}
	
 	/**
 	 * 加密<br>
 	 * 用私钥加密
 	 * 
 	 * @param plainBytes
 	 * @param key
 	 * @return
 	 * @throws Exception
 	 */
	@Override
	public String encodeByPrivateKey(String plainText, String base64PrivateKeyText) throws GeneralSecurityException {
		// 取得私钥
 		PrivateKey privateKey = toPrivateKey(base64PrivateKeyText);
 		// 对数据加密
		return this.encode(plainText, privateKey);
	}
	
	@Override
	public String encode(String plainText, PrivateKey privateKey) throws GeneralSecurityException {
		// 对数据加密
		return StringUtils.newStringUtf8(this.encode(plainText.getBytes(), privateKey));
	}
	
 	public byte[] encodeByPrivateKey(byte[] plainBytes, String base64PrivateKeyText) throws GeneralSecurityException {
 		// 取得私钥
 		PrivateKey privateKey = toPrivateKey(base64PrivateKeyText);
 		// 对数据加密
 		return this.encode(plainBytes, privateKey);
 	}
 	
 	public byte[] encode(byte[] plainBytes, PrivateKey privateKey) throws GeneralSecurityException {
 		// 取得Cipher对象
 	 	Cipher cipher = CipherUtils.getEncryptCipher(Algorithm.KEY_RSA, privateKey);
 	 	// 对数据分段加密  
		byte[] encryptedData = CipherUtils.segment(cipher, plainBytes, MAX_ENCRYPT_BLOCK);
		// 对数据加密
 	 	return new String(Hex.encodeHex(encryptedData)).getBytes();
 	}
	
 	
 	
 }

