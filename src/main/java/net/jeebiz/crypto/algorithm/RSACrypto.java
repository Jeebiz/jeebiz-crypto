package net.jeebiz.crypto.algorithm;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import net.jeebiz.crypto.utils.StringUtils;




/**
 * 
 * @className: RSAHelper
 *  加解密工具类
 */
public final class RSACrypto {
	
	public static final String public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIyFsRh3vbNB4GrYCsmw2UdNAq5QrnHrml8JXM"+
											"KRhCCGF99wDLT3bhoL8YvBywP3eWBX3IMHL6DKbDp3l1sqLT0LQ0TFRMwnvnLXsmzRjubeJiEfyY"+
											"47FdtZGji4rllrekloqohypkcivHac7HOeuCsWd9vxD7gGZEig5T9Tu8QwIDAQAB";
	
	public static final String private_key = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIjIWxGHe9s0HgatgKybDZR00Crl"+
											"CuceuaXwlcwpGEIIYX33AMtPduGgvxi8HLA/d5YFfcgwcvoMpsOneXWyotPQtDRMVEzCe+cteybN"+
											"GO5t4mIR/JjjsV21kaOLiuWWt6SWiqiHKmRyK8dpzsc564KxZ32/EPuAZkSKDlP1O7xDAgMBAAEC"+
											"gYA/22nIsTu9hoNOEsozyt94I2Db5bpFVC7PrZYBjl3o1gjNyfbw89RIWcddQNUT401tGHs0bon+"+
											"+tEQHquxqwggs4tr9DqWVttdOk+diSnmuneyahBRpgh42jXkf5NBZZZcIRx4Ry2TwtxHgcfx+Bqx"+
											"gEjsyQKw6f/g1UceZftqQQJBAM5bF4aNHbeg35tijZ40yv8ldc0x5jLJnUTQGer+LtCrm+GIMmhw"+
											"bE5clZJZV7qDK7pMjJvP7INz+/EWXEZGSAsCQQCpsG+K/Ho732E39WQP8AVGQR2nRDlqTXi6h+pw"+
											"ZAIan66ucd29wL0hojF9XcaD4wWC+6PXyYbVLeaPD/eS5aepAkEAnUlfYCZ1rT6I0aZH7Xut8tZ5"+
											"uQK8xJ9aKVY5Ox2tT05OjZRDX8m5M+1r8FX7AWXz0ZeBYU4Vp4ijU3rIsKPnSwJAZg3F1+omvZGI"+
											"D7aW2nr5QRpyciG3AjbbsBuEJNoQ5eA5l5LF0JR1ax/38bUPakyECRW8oVADtnxnmIz60a8rGQJA"+
											"MvDY4TlvOsvQcYJQMHHbvSeKgAP8mOJBM+QG4YOyBxAjDhxS3k6jkTWSqZh5xECpNQo+Exjlzgjf"+
											"NCxBVSCuHQ==";
    
   /**
    * RSA加密
    * @param text 需要加密的明文
    * @return 密文
    * @throws Exception
    */
    public final static String encrypt(String text) throws Exception {
    	byte[] pubkey_bytes = Base64.decodeBase64(public_key);
    	
        PublicKey pubkey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubkey_bytes));
        StringBuffer sbf = new StringBuffer(200);
        try {
            text = URLEncoder.encode(text, "UTF-8");//用这个的原因是为了支持汉字、汉字和英文混排,解密方法中同理
            byte[] plainByte = text.getBytes();
            ByteArrayInputStream bays = new ByteArrayInputStream(plainByte);
            // 每次加密100字节
            byte[] readByte = new byte[100];
            int n = 0;
            // 为了支持超过117字节，每次加密100字节。
            while ((n = bays.read(readByte)) > 0) {
                if (n >= 100) {
                    sbf.append(StringUtils.getHexString(encrypt(readByte, pubkey)));
                } else {
                    byte[] tt = new byte[n];
                    for (int i = 0; i < n; i++) {
                        tt[i] = readByte[i];
                    }
                    sbf.append(StringUtils.getHexString(encrypt(tt, pubkey)));
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return sbf.toString();
    }
    
    
    private static byte[] encrypt(byte[] text, PublicKey uk) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, uk);
		return cipher.doFinal(text);
    }
    
    /**
     * RSA解密
     * @param data 密文
     * @return 明文
     * @throws IOException 
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeySpecException 
     * @throws Exception
     */
    public final static String decrypt(String data) throws IOException{
    	byte[] prikey_bytes = Base64.decodeBase64(private_key);
        PrivateKey prikey = null;
		try {
			prikey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(prikey_bytes));
		} catch (InvalidKeySpecException e1) {
			e1.printStackTrace();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		}
        String rrr = "";
        StringBuffer sb = new StringBuffer(100);
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(
                    data.getBytes());
             //此处之所以是 256，而不是128的原因是因为有一个16进行的转换，所以由128变为了256
            byte[] readByte = new byte[256];
            int n = 0;
            while ((n = bais.read(readByte)) > 0) {
                if (n >= 256) {
                    sb.append(new String(decrypt(StringUtils.getHexBytes(readByte), prikey)).trim());
                } else {

                }
            }
            rrr = URLDecoder.decode(sb.toString(), "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return rrr;
    }

    private static byte[] decrypt(byte[] src, PrivateKey rk) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, rk);
        return cipher.doFinal(src);
    }

    
    public static void genKey() throws Exception {
        //产生一个RSA密钥生成器KeyPairGenerator(顾名思义：一对钥匙生成器)
//      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//      // 定义密钥长度1024位
//      keyGen.initialize(1024);
//      // 通过KeyPairGenerator产生密钥,注意：这里的key是一对钥匙！！
//      KeyPair key = keyGen.generateKeyPair();        
//      PublicKey pubKey = key.getPublic();
//      String pub_key = encod(pubKey.getEncoded());
//      System.out.println("公钥: " + pub_key);
//        
//      PrivateKey priKey = key.getPrivate();
//      String pri_key = encod(priKey.getEncoded());
//      System.out.println("私钥: " + pri_key);
    }
    
    public static void main(String[] args) throws Exception {
    	 String s = RSACrypto.encrypt("test/jxjh/xqzxjh/xqzxjhcj/XqzxjhrwBjck.jsp");
         System.out.println("密文: " + s);
         System.out.println("明文: " + RSACrypto.decrypt(s));
	}
}
