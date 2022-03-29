package org.notsay.cipher.common.constants;

/**
 * @description:
 * @author: dsy
 * @date: 2022/3/29 15:33
 */
public class BaseConstants {
    /**
     * sm4加密编码方式
     */
    public static final String SM4_ENCODING = "UTF-8";

    /**
     * sm4加密算法名称
     */
    public static final String SM4_ALGORITHM_NAME = "SM4";

    /**
     * sm4加密方式
     * 加密算法/分组加密模式/分组填充方式
     * PKCS5Padding-以8个字节为一组进行分组加密
     * 定义分组加密模式使用：PKCS5Padding
     */
    public static final String SM4_ALGORITHM_NAME_CBC_PADDING = "SM4/CBC/PKCS5Padding";

    /**
     * sm4加密秘钥默认位数
     */
    public static final int SM4_KET_LENGTH = 128;

}