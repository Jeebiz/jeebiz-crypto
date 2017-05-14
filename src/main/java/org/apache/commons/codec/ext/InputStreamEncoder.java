package org.apache.commons.codec.ext;

/**
 * @title: InputStreamEncoder.java
 * @package org.apache.commons.codec.ext
 * @fescription: TODO(添加描述)
 * @author: wandalong
 * @date : 下午11:28:09 2014-9-27 
 */
import java.io.IOException;
import java.io.InputStream;

public interface InputStreamEncoder {

	public String encode(InputStream plantStream) throws IOException;
	
}
