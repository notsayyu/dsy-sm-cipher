package org.notsay.cipher.common.util;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.notsay.cipher.common.enums.Code;
import org.notsay.cipher.common.exception.CipherBusinessException;

import java.security.Security;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.notsay.cipher.common.constants.BaseConstants.ENCODING;

/**
 * @description:
 * @author: dsy
 * @date: 2022/3/29 20:40
 */
public class Sm3Utils {
    private static final Logger log = Logger.getLogger(Sm4Utils.class.getName());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * sm3算法加密
     *
     * @return 返回加密后，固定长度=32的16进制字符串
     */
    public static String encrypt(String param) {
        // 将返回的hash值转换成16进制字符串
        String resultHexString = "";
        try {
            // 将字符串转换成byte数组
            byte[] srcData = param.getBytes(ENCODING);
            // 调用hash()
            byte[] resultHash = hash(srcData);
            // 将返回的hash值转换成16进制字符串
            resultHexString = ByteUtils.toHexString(resultHash);
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new CipherBusinessException(Code.SM3_PROTECT_ERROR);
        }
        return resultHexString;
    }

    /**
     * 判断源数据与加密数据是否一致
     * 通过验证原数组和生成的hash数组是否为同一数组，验证2者是否为同一数据
     */
    public static boolean verify(String srcStr, String sm3HexString) {
        boolean flag = false;
        try {
            byte[] srcData = srcStr.getBytes(ENCODING);
            byte[] sm3Hash = ByteUtils.fromHexString(sm3HexString);
            byte[] newHash = hash(srcData);
            if (Arrays.equals(newHash, sm3Hash)) {
                flag = true;
            }
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new CipherBusinessException(Code.SM3_VERIFY_ERROR);
        }
        return flag;
    }


    /**
     * 返回长度=32的byte数组
     * 生成对应的hash值
     */
    public static byte[] hash(byte[] srcData) {
        SM3Digest digest = new SM3Digest();
        digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    }

    public static void main(String[] args) {
        String secretText = encrypt("汤上塔，塔骨汤，汤烫塔");
        System.out.println(secretText);
        System.out.println(verify("汤上塔，塔骨汤，汤烫塔", secretText));
        System.out.println(verify("汤上塔，塔骨汤，汤烫塔2", secretText));
    }

}