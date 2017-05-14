package org.apache.commons.codec.ext;

import java.security.cert.Certificate;
import java.util.Date;

/**
 * 
 * @description:证书验证接口
 * @author <a href="mailto:hnxyhcwdl1003@163.com">wandalong</a>
 * @date 2014-9-29
 */
public interface CertificateVerifier {

	/**
	 * 
	 * @description: 判断证书是否过期
	 * @author : wandalong
	 * @date : 2014-9-29
	 * @time : 下午1:43:11 
	 * @param date
	 * @param certificate
	 * @return
	 */
	public boolean expire(Date date, Certificate certificate);
	public boolean expire(Certificate certificate);
	public boolean expire(String certificatePath);
	public boolean expire(Date date, String certificatePath);
	
	public boolean verify(String keyStorePath, String alias,String password);
	
	public boolean verify(Date date, String keyStorePath,String alias, String password);
	
	public boolean verify(byte[] data, String sign,String certificatePath) throws Exception;
	
}
