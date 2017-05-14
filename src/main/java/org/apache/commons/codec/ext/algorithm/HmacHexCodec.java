package org.apache.commons.codec.ext.algorithm;

import java.security.GeneralSecurityException;

import org.apache.commons.codec.BinaryEncoder;
import org.apache.commons.codec.EncoderException;
import org.apache.commons.codec.StringEncoder;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.ext.StringVerifier;
import org.apache.commons.codec.ext.enums.Algorithm;
import org.apache.commons.codec.ext.utils.HmacUtils;
import org.apache.commons.codec.ext.utils.SecretKeyUtils;
import org.apache.commons.codec.ext.utils.StringUtils;
/**
 * 
 * @package org.apache.commons.codec.ext.algorithm
 * @className: HmacHexCodec
 * @description: MAC消息摘要组件
 * @author : wandalong
 * @date : 2014-9-28
 * @time : 下午7:37:41
 */
public class HmacHexCodec implements StringEncoder,BinaryEncoder,StringVerifier {
	
	private byte[] base64Key = null;
	private String algorithm = Algorithm.KEY_HMAC_MD5;
	private static HmacHexCodec instance = null;
	
	private HmacHexCodec(){};
	
	private HmacHexCodec(byte[] base64Key){
		this.base64Key = base64Key;
	};
	
	private HmacHexCodec(byte[] base64Key,String algorithm){
		this.base64Key = base64Key;
		this.algorithm = algorithm;
	};
	
	public static HmacHexCodec getInstance(byte[] base64Key){
		instance= (instance==null)?instance=new HmacHexCodec(base64Key):instance;
		instance.base64Key = base64Key;
		return  instance;
	}
	
	public static HmacHexCodec getInstance(byte[] base64Key,String algorithm){
		instance= (instance==null)?instance=new HmacHexCodec(base64Key):instance;
		instance.base64Key = base64Key;
		instance.algorithm = algorithm;
		return  instance;
	}
	
	public Object encode(Object plainObject) throws EncoderException {
		if (plainObject == null) {
            return null;
        } else if (plainObject instanceof String) {
            return encode((String) plainObject);
        } else {
            throw new EncoderException("Objects of type " + plainObject.getClass().getName() + " cannot be encoded using MD4HexCodec");
        }
	}
	
	public byte[] encode(byte[] plainBytes) throws EncoderException {
		try {
			//获取Hmac消息摘要信息
			return new String(Hex.encodeHex(HmacUtils.hmac(plainBytes, base64Key, algorithm), false)).getBytes();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] encode(byte[] plainBytes, int times) throws EncoderException{
		try {
			//第一次加密
			byte[] binaryData = HmacUtils.hmac(plainBytes, base64Key, algorithm);
			for (int i = 0; i < times - 1; i++) {
				//多次加密
				binaryData = HmacUtils.hmac(binaryData, base64Key, algorithm);
			}
			return new String(Hex.encodeHex(binaryData, false)).getBytes();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public String encode(String plainText) throws EncoderException {
		try {
			//获取Hmac消息摘要信息
			return Hex.encodeHexString(HmacUtils.hmac(plainText.getBytes(), base64Key, algorithm)).toUpperCase();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public String encode(String plainText, int times)  throws EncoderException{
		try {
			//第一次加密
			byte[] binaryData = HmacUtils.hmac(plainText.getBytes(), base64Key, algorithm);
			for (int i = 0; i < times - 1; i++) {
				//多次加密
				binaryData = HmacUtils.hmac(binaryData, base64Key, algorithm);
			}
			return Hex.encodeHexString(binaryData).toUpperCase();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] encodeHmacMD2(byte[] plainBytes) throws EncoderException {
		//获取HmacMD2消息摘要信息
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_MD2).encode(plainBytes);
	}
	
	public String encodeHmacMD2(String plainText) throws EncoderException {
		//获取HmacMD2消息摘要信息
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_MD2).encode(plainText);
	}
	
	public byte[] encodeHmacMD4(byte[] plainBytes) throws EncoderException {
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_MD4).encode(plainBytes);
	}
	
	public String encodeHmacMD4(String plainText) throws EncoderException {
		//获取HmacMD4消息摘要信息
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_MD4).encode(plainText);
	}
	
	public byte[] encodeHmacSHA1(byte[] plainBytes) throws EncoderException {
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA1).encode(plainBytes);
	}
	
	public String encodeHmacSHA1(String plainText) throws EncoderException {
		//获取HmacSHA1消息摘要信息
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA1).encode(plainText);
	}
	
	public byte[] encodeHmacSHA224(byte[] plainBytes) throws EncoderException {
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA224).encode(plainBytes);
	}
	
	public String encodeHmacSHA224(String plainText) throws EncoderException {
		//获取HmacSHA224消息摘要信息
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA224).encode(plainText);
	}
	
	public byte[] encodeHmacSHA256(byte[] plainBytes) throws EncoderException {
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA256).encode(plainBytes);
	}
	
	public String encodeHmacSHA256(String plainText) throws EncoderException {
		//获取HmacSHA256消息摘要信息
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA256).encode(plainText);
	}
	
	public byte[] encodeHmacSHA384(byte[] plainBytes) throws EncoderException {
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA384).encode(plainBytes);
	}
	
	public String encodeHmacSHA384(String plainText) throws EncoderException {
		//获取HmacSHA384消息摘要信息
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA384).encode(plainText);
	}
	
	public byte[] encodeHmacSHA512(byte[] plainBytes) throws EncoderException {
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA512).encode(plainBytes);
	}
	
	public String encodeHmacSHA512(String plainText) throws EncoderException {
		//获取HmacSHA512消息摘要信息
		return HmacHexCodec.getInstance(base64Key, Algorithm.KEY_HMAC_SHA512).encode(plainText);
	}
	
	public static String getEncryptKey(String plainText,String base64Key) throws GeneralSecurityException{
		return DESBase64Codec.getInstance().encode(plainText, base64Key);
	}

	public static  String getDecryptKey(String encryptedText,String base64Key) throws GeneralSecurityException{
		return DESBase64Codec.getInstance().decode(encryptedText, base64Key);
	}
	
	/**
	 * 密码验证方法
	 * @throws EncoderException 
	 */
	public boolean verify(String plainText, String encrypt) throws EncoderException{
		return encode(plainText).equals(encrypt);
	}

	/**
	 * 重载一个多次加密时的密码验证方法
	 * @throws EncoderException 
	 */
	public boolean verify(String plainText, String encrypt, int times) throws EncoderException{
		return encode(plainText, times).equals(encrypt);
	}
	
	/**
	 * 进行相关的摘要算法的处理展示
	 * @throws Exception 
	 * **/
	public static void main(String[] args) throws Exception {
		
		String base64Key1 = StringUtils.newStringUtf8(DESBase64Codec.getInstance().initkey());
		System.out.println("base64Key："+base64Key1);
		
		System.out.println("学校随机秘钥："+getEncryptKey("011111454",base64Key1));
		//成绩加密密钥：学号、课程号、成绩、学校随机密钥（存二维表实例下的表）
		String keyText = "3000611031-72120170-不及格-"+ getDecryptKey(getEncryptKey("011111454",base64Key1),base64Key1) ;
		System.out.println("keyText:"+keyText);
		
		HmacHexCodec codec1 = HmacHexCodec.getInstance(Base64.encodeBase64(keyText.getBytes()));
		
		System.out.println("================================================================:" );
		System.out.println("test:" +codec1.encode("不及格"));
		System.out.println("123:" + codec1.encode("123"));
		System.out.println("123456789:" + codec1.encode("123456789"));
		System.out.println("sarin:" + codec1.encode("sarin").length());
		
		System.out.println("================================================================:" );
		
		String plainText="HmacMD5消息摘要";
		//初始化HmacMD5的密钥
		byte[] base64Key = SecretKeyUtils.genBinarySecretKey(Algorithm.KEY_HMAC_MD5);
		System.out.println("Hmac的密钥:"+ new String(base64Key));
		System.out.println("原文："+plainText);
		
		HmacHexCodec codec = HmacHexCodec.getInstance(base64Key);
		//获取HmacMD5消息摘要信息
		System.out.println("HmacMD5算法摘要："+ codec.encode(plainText));
		
		//初始化密钥
		codec = HmacHexCodec.getInstance(base64Key,Algorithm.KEY_HMAC_SHA256);
		//获取摘要信息
		System.out.println("HmacSHA256算法摘要："+ codec.encode(plainText));
		
		//初始化密钥
		codec = HmacHexCodec.getInstance(base64Key,Algorithm.KEY_HMAC_SHA1);
		//获取摘要信息
		System.out.println("HmacSHA1算法摘要："+ codec.encode(plainText));
		
		//初始化密钥
		codec = HmacHexCodec.getInstance(base64Key,Algorithm.KEY_HMAC_SHA384);
		//获取摘要信息
		System.out.println("HmacSHA384算法摘要："+codec.encode(plainText));
		
		//初始化密钥
		codec = HmacHexCodec.getInstance(base64Key,Algorithm.KEY_HMAC_SHA512);
		//获取摘要信息
		System.out.println("HmacSHA512算法摘要："+ codec.encode(plainText));
		
		System.out.println("================以下的算法支持是bouncycastle支持的算法，sun java6不支持=======================");
		
		//初始化密钥
		codec = HmacHexCodec.getInstance(base64Key,Algorithm.KEY_HMAC_MD2);
		//获取摘要信息
		System.out.println("Bouncycastle HmacMD2算法摘要："+ codec.encode(plainText));
		
		//初始化密钥
		codec = HmacHexCodec.getInstance(base64Key,Algorithm.KEY_HMAC_MD4);
		//获取摘要信息
		System.out.println("Bouncycastle HmacMD4算法摘要："+ codec.encode(plainText));
		
		//初始化密钥
		codec = HmacHexCodec.getInstance(base64Key,Algorithm.KEY_HMAC_SHA224);
		//获取摘要信息
		System.out.println("Bouncycastle HmacSHA224算法摘要："+ codec.encode(plainText));
		
		/*base64Key：uoMHT55MO5E=
		学校随机秘钥：5mAnUwZA8QDjP0OEVdp3Kw==
		keyText:3000611031-72120170-不及格-011111454
		================================================================:
		test:DE61367451D1407C58ED95E9B68A40A3
		123:A382304CFE403D89CCA4541042406743
		123456789:8EB1D7D187610A6CC9EEA3D47BEDE525
		sarin:32
		================================================================:
		Hmac的密钥:9F��k*RcQ�0όq7�&��pb�m%�5��2��g3�c'��_��uC�i/��D�d����
		�z�A
		原文：HmacMD5消息摘要
		HmacMD5算法摘要：B8C2DFC7AFE9ABC55ED2C45FB7DE7F3B
		HmacSHA256算法摘要：2834EB747E9BE0B63DB89EA09DEB07F751E4634176C3E1F5E2DCC913BE19CC85
		HmacSHA1算法摘要：86900B93B6B7498751A4959703754600AF197472
		HmacSHA384算法摘要：0E937B9803540FF80F7F80A852B33780426634EED29AF7A56170F7C90954F4D1D28F4F849CF9068E2B242F452EB3429F
		HmacSHA512算法摘要：39364A0E4122828E9D939662AF9016DAE30F4CFF64A368B3EEA9AB47E48F2E569420BC30747FB6154B4A7B10CB19669EB96F91DCDE7B19DE964CDF23B31807EA
		================以下的算法支持是bouncycastle支持的算法，sun java6不支持=======================
		Bouncycastle HmacMD2算法摘要：2758AD209FABC12CD51EAD8431042BB5
		Bouncycastle HmacMD4算法摘要：5A12D7287EC27F7A8B5313241319E9AE
		Bouncycastle HmacSHA224算法摘要：3C293374D37BBC448A328BADC330A89B2CDD58E6F5AE83EB5F8B144C
*/
	}
	
}
