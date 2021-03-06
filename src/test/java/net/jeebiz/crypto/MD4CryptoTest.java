/**
 * Copyright (c) 2018, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package net.jeebiz.crypto;

import org.apache.commons.codec.binary.Hex;

import net.jeebiz.crypto.algorithm.MD4Crypto;

public class MD4CryptoTest {

	
	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		String str="bouncycast 的消息摘要算法";
		System.out.println("原文："+str);
		byte[] data1= MD4Crypto.getInstance().encode(str.getBytes());
		
		System.out.println("MD4的消息摘要算法值："+data1.toString());
		System.out.println("MD4做十六进制编码处理的消息摘要算法值："+Hex.encodeHexString(data1));
		
		
	}

}
