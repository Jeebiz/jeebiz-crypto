package org.apache.commons.codec.ext;

/**
 * @title: InputStreamEncoder.java
 * @package org.apache.commons.codec.ext
 * @fescription: TODO(添加描述)
 */
import java.io.IOException;
import java.io.InputStream;

public interface InputStreamEncoder {

	public String encode(InputStream plantStream) throws IOException;
	
}
