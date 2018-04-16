package net.jeebiz.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import net.jeebiz.crypto.KeyPairCodec.KeyPairEntry;
import net.jeebiz.crypto.algorithm.RSABase64Crypto;
import org.junit.Test;

/**
 * 
 * @author 梁栋
 * @version 1.0
 * @since 1.0
 */
public class RSABase64CryptoTest {
	@Test
	public void test0() throws Exception {

	}

	// @Test
	public void atest1() throws Exception {

		System.out
				.println("------------------固定key---------------------------------------------- ");
		String publicKey = RSABase64Crypto.public_key;
		String privateKey = RSABase64Crypto.private_key;

		String s = RSABase64Crypto.getInstance().encodeByPublicKey(
				"aq_03,android,123456", publicKey);
		System.out.println("密文: " + s);
		System.out.println("明文: "
				+ RSABase64Crypto.getInstance()
						.decodeByPrivateKey(s, privateKey));

		System.out
				.println("---------------------------------------------------------------- ");

		String s3 = RSABase64Crypto.getInstance().encodeByPublicKey(
				"test/jxjh/xqzxjh/xqzxjhcj/XqzxjhrwBjck.jsp", publicKey);
		System.out.println("密文: " + s3);
		System.out.println("明文: "
				+ RSABase64Crypto.getInstance().decodeByPrivateKey(s3,
						privateKey));

		System.out
				.println("---------------------------------------------------------------- ");

	}

	// @Test
	public void atest2() throws Exception {

		System.out
				.println("--------------------------------初始化key-------------------------------- ");
		KeyPairEntry keyPair = RSABase64Crypto.getInstance().initKeyEntry(512);
		String publicKey = keyPair.getPublicKey();
		String privateKey = keyPair.getPrivateKey();
		System.out.println("公钥: \n\r" + publicKey);
		System.out.println("私钥： \n\r" + privateKey);

		System.out
				.println("--------------------------------公钥加密——私钥解密-------------------------------- ");
		String inputStr = "abc";
		byte[] data = inputStr.getBytes();

		byte[] encodedData = RSABase64Crypto.getInstance().encodeByPublicKey(
				data, publicKey);

		byte[] decodedData = RSABase64Crypto.getInstance().decodeByPrivateKey(
				encodedData, privateKey);

		String outputStr = new String(decodedData);
		System.out.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		assertEquals(inputStr, outputStr);

	}

	// @Test
	public void atestSign() throws Exception {

		System.out
				.println("--------------------------------初始化key-------------------------------- ");
		KeyPairEntry keyPair = RSABase64Crypto.getInstance().initKeyEntry(1024);
		String publicKey = keyPair.getPublicKey();
		String privateKey = keyPair.getPrivateKey();
		System.out.println("公钥: \n\r" + publicKey);
		System.out.println("私钥： \n\r" + privateKey);

		System.out
				.println("--------------------------------私钥加密——公钥解密-------------------------------- ");
		String inputStr = "sign";

		String encodedData = RSABase64Crypto.getInstance().encodeByPrivateKey(
				inputStr, privateKey);

		String decodedData = RSABase64Crypto.getInstance().decodeByPublicKey(
				encodedData, publicKey);

		String outputStr = new String(decodedData);
		System.out.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		assertEquals(inputStr, outputStr);

		System.out
				.println("--------------------------------私钥签名——公钥验证签名-------------------------------- ");
		// 产生签名
		String sign = RSABase64Crypto.getInstance().sign(encodedData.getBytes(),
				privateKey);
		System.out.println("签名:\r" + sign);

		// 验证签名
		boolean status = RSABase64Crypto.getInstance().verify(
				encodedData.getBytes(), publicKey, sign);
		System.out.println("状态:\r" + status);
		assertTrue(status);

	}

}
