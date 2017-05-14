package org.apache.commons.codec.ext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.apache.commons.codec.ext.KeyPairCodec.KeyPairEntry;
import org.apache.commons.codec.ext.algorithm.RSAHexCodec;
import org.junit.Test;

/**
 * 
 * @author 梁栋
 * @version 1.0
 * @since 1.0
 */
public class RSAHexCodecTest {

	@Test
	public void test0() throws Exception {

	}

	// @Test
	public void atest1() throws Exception {

		System.out
				.println("------------------固定key---------------------------------------------- ");
		String publicKey = RSAHexCodec.public_key;
		String privateKey = RSAHexCodec.private_key;

		String s = RSAHexCodec.getInstance().encodeByPublicKey(
				"aq_03,android,123456", publicKey);
		System.out.println("密文: " + s);
		System.out.println("明文: "
				+ RSAHexCodec.getInstance().decodeByPrivateKey(s, privateKey));

		System.out
				.println("---------------------------------------------------------------- ");

		String s3 = RSAHexCodec
				.getInstance()
				.encodeByPublicKey(
						"jwglxt/jxjh/xqzxjh/xqzxjhcj/XqzxjhrwBjck.jspjwglxt/jxjh/xqzxjh/xqzxjhcj/XqzxjhrwBjck.jsp",
						publicKey);
		System.out.println("密文: " + s3);
		System.out.println("明文: "
				+ RSAHexCodec.getInstance().decodeByPrivateKey(s3, privateKey));

		System.out
				.println("---------------------------------------------------------------- ");

	}

	// @Test
	public void atest2() throws Exception {

		System.out
				.println("--------------------------------初始化key-------------------------------- ");
		KeyPairEntry keyPair = RSAHexCodec.getInstance().initKeyEntry(512);
		String publicKey = keyPair.getPublicKey();
		String privateKey = keyPair.getPrivateKey();
		System.out.println("公钥: \n\r" + publicKey);
		System.out.println("私钥： \n\r" + privateKey);

		System.out
				.println("--------------------------------公钥加密——私钥解密-------------------------------- ");
		String inputStr = "abc";
		byte[] data = inputStr.getBytes();

		byte[] encodedData = RSAHexCodec.getInstance().encodeByPublicKey(data,
				publicKey);

		byte[] decodedData = RSAHexCodec.getInstance().decodeByPrivateKey(
				encodedData, privateKey);

		String outputStr = new String(decodedData);
		System.out.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		assertEquals(inputStr, outputStr);

	}

	// @Test
	public void atestSign() throws Exception {

		System.out
				.println("--------------------------------初始化key-------------------------------- ");
		KeyPairEntry keyPair = RSAHexCodec.getInstance().initKeyEntry(1024);
		String publicKey = keyPair.getPublicKey();
		String privateKey = keyPair.getPrivateKey();
		System.out.println("公钥: \n\r" + publicKey);
		System.out.println("私钥： \n\r" + privateKey);

		System.out
				.println("--------------------------------私钥加密——公钥解密-------------------------------- ");
		String inputStr = "sign";

		String encodedData = RSAHexCodec.getInstance().encodeByPrivateKey(
				inputStr, privateKey);

		String decodedData = RSAHexCodec.getInstance().decodeByPublicKey(
				encodedData, publicKey);

		String outputStr = new String(decodedData);
		System.out.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		assertEquals(inputStr, outputStr);

		System.out
				.println("--------------------------------私钥签名——公钥验证签名-------------------------------- ");
		// 产生签名
		String sign = RSAHexCodec.getInstance().sign(encodedData.getBytes(),
				privateKey);
		System.out.println("签名:\r" + sign);

		// 验证签名
		boolean status = RSAHexCodec.getInstance().verify(
				encodedData.getBytes(), publicKey, sign);
		System.out.println("状态:\r" + status);
		assertTrue(status);

	}

}
