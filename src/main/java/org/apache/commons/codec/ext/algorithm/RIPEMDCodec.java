package org.apache.commons.codec.ext.algorithm;
/**
 * 
 * @package org.apache.commons.codec.ext.algorithm
 * @className: RIPEMDCodec
 * @description: RIPEMD算法
				 RIPEMD（RACE Integrity Primitives Evaluation Message Digest，RACE原始完整性校验消息摘要），
				 是Hans Dobbertin等3人在md4,md5的基础上，于1996年提出来的。算法共有4个标准128、160、256和320，
				 其对应输出长度分别为16字节、20字节、32字节和40字节。不过，让人难以致信的是RIPEMD的设计者们根本
				 就没有真正设计256和320位这2种标准，他们只是在128位和160位的基础上，修改了初始参数和s-box来达到
				 输出为256和320位的目的。所以，256位的强度和128相当，而320位的强度和160位相当。RIPEMD建立在md的
				 基础之上，所以，其添加数据的方式和md5完全一样。
 */
public class RIPEMDCodec {
	
}
