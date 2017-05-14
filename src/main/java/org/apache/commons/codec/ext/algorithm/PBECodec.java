package org.apache.commons.codec.ext.algorithm;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.ext.Codec;
import org.apache.commons.codec.ext.enums.Algorithm;
import org.apache.commons.codec.ext.utils.CipherUtils;
import org.apache.commons.codec.ext.utils.SecretKeyUtils;
import org.apache.commons.codec.ext.utils.StringUtils;
/**
 * 
 * @description: PBE——Password-based encryption（基于密码加密）。其特点在于口令由用户自己掌管，不借助任何物理媒体；采用随机数（这里我们叫做盐）杂凑多重加密等方法保证数据的安全性。是一种简便的加密方式。 
 * 使用java6提供的PBEWITHMD5andDES算法进行展示
 * JAVA6支持以下任意一种算法
 * PBEWITHMD5ANDDES
 * PBEWITHMD5ANDTRIPLEDES
 * PBEWITHSHAANDDESEDE
 * PBEWITHSHA1ANDRC2_40
 * PBKDF2WITHHMACSHA1
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-29
 */
public class PBECodec implements Codec {
	
	private static PBECodec instance = null;
	private PBECodec(){};
	public static PBECodec getInstance(){
		instance= (instance==null)?instance=new PBECodec():instance;
		return  instance;
	}
	
	/**
	 * 迭代次数
	 * */
	public static final int ITERATION_COUNT=100;
	
	/**
	 * 
	 * @description: 盐初始化:盐长度必须为8字节
	 * @author : wandalong
	 * @date : 2014-9-29
	 * @time : 下午7:46:00 
	 * @return byte[] 盐
	 * @throws GeneralSecurityException
	 */
	public byte[] initkey() throws GeneralSecurityException {
		//实例化安全随机数
		SecureRandom random = new SecureRandom();
		//产出盐
		return random.generateSeed(8);
	}

	public Key toKey(byte[] password) throws GeneralSecurityException {
		return toKey(StringUtils.newStringUtf8(password));
	}
	
	/**
	 * 
	 * @description: 转换密钥
	 * @author : wandalong
	 * @date : 2014-9-29
	 * @time : 下午7:51:19 
	 * @param password 密码
	 * @return Key 密钥
	 * @throws GeneralSecurityException
	 */
	public Key toKey(String password) throws GeneralSecurityException{
		return SecretKeyUtils.genPBEKey(password, Algorithm.KEY_PBE_MD5_DES);
	}
	
	/**
	 * 加密
	 * @param data 待加密数据
	 * @param password 密码
	 * @param salt 盐
	 * @return byte[] 加密数据
	 * 
	 * */
	public byte[] encode(byte[] plainBytes,String password,byte[] salt) throws Exception{
		//转换密钥
		Key key= toKey(password);
		//实例化PBE参数材料
		PBEParameterSpec paramSpec = new  PBEParameterSpec(salt,ITERATION_COUNT);
		//实例化
		Cipher cipher = CipherUtils.getCipher(Algorithm.KEY_PBE_MD5_DES);
		//初始化
		cipher.init(Cipher.ENCRYPT_MODE, key,paramSpec);
		//执行操作
		return cipher.doFinal(plainBytes);
	}
	
	/**
	 * 解密
	 * @param encryptedBytes 待解密数据
	 * @param password 密码
	 * @param salt 盐
	 * @return byte[] 解密数据
	 * 
	 * */
	public byte[] decode(byte[] encryptedBytes,String password,byte[] salt) throws Exception{
		//转换密钥
		Key key = toKey(password);
		//实例化PBE参数材料
		PBEParameterSpec paramSpec=new PBEParameterSpec(salt,ITERATION_COUNT);
		//实例化
		Cipher cipher=Cipher.getInstance(Algorithm.KEY_PBE_MD5_DES);
		//初始化
		cipher.init(Cipher.DECRYPT_MODE, key,paramSpec);
		//执行操作
		return cipher.doFinal(encryptedBytes);
	}
	
	
	/**
	 * 使用PBE算法对数据进行加解密
	 * @throws Exception 
	 * 
	 */
	public static void main(String[] args) throws Exception {
		//待加密数据
		String str="PBE";
		//设定的口令密码
		String password="azsxdc";
		
		System.out.println("原文：/t"+str);
		System.out.println("密码：/t"+password);
		
		//初始化盐
		byte[] salt = PBECodec.getInstance().initkey();
		System.out.println("盐：/t"+Base64.encodeBase64String(salt));
		//加密数据
		byte[] data=PBECodec.getInstance().encode(str.getBytes(), password, salt);
		System.out.println("加密后：/t"+Base64.encodeBase64String(data));
		//解密数据
		data=PBECodec.getInstance().decode(data, password, salt);
		System.out.println("解密后："+new String(data));
	}

	
}
