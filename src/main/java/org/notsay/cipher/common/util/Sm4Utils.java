package org.notsay.cipher.common.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.notsay.cipher.common.enums.Code;
import org.notsay.cipher.common.exception.CipherBusinessException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.logging.Logger;

import static org.notsay.cipher.common.constants.BaseConstants.*;

/**
 * @description:
 * @author: dsy
 * @date: 2022/3/29 15:35
 */
public class Sm4Utils {
    private static final Logger log = Logger.getLogger(Sm4Utils.class.getName());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成系统秘钥
     */
    public static String generateKsy() {
        try {
            return generateKsy(SM4_KET_LENGTH);
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new CipherBusinessException(Code.SM4_GEN_KEY_ERROR);
        }
    }

    public static String generateKsy(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(SM4_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.init(keySize, new SecureRandom());
        return SelfByteUtils.byteToHex(keyGenerator.generateKey().getEncoded());
    }

    /**
     * sm4加密
     *
     * @return 返回16进制的加密字符串
     * @explain 加密模式：CBC
     * 16进制密钥（忽略大小写）
     */
    public static String protectMsg(String secretKey, String param) {
        try {
            param = param == null ? "" : param;
            String result = "";
            // 16进制字符串-->byte[]
            byte[] keyData = SelfByteUtils.hexToByte(secretKey);
            // String-->byte[]
            byte[] srcData = param.getBytes(ENCODING);
            // 加密后的数组
            byte[] cipherArray = encrypt_Cbc_Padding(keyData, srcData);
            // byte[]-->hexString
            result = ByteUtils.toHexString(cipherArray);
            return result;
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new CipherBusinessException(Code.SM4_PROTECT_ERROR);
        }

    }

    /**
     * sm4解密
     *
     * @explain 解密模式：采用CBC
     */
    public static String uncoverMsg(String secretKey, String param) {
        try {
            param = param == null ? "" : param;
            // 用于接收解密后的字符串
            String result = "";
            // hexString-->byte[]
            byte[] keyData = SelfByteUtils.hexToByte(secretKey);
            // hexString-->byte[]
            byte[] resultData = ByteUtils.fromHexString(param);
            // 解密
            byte[] srcData = decrypt_Cbc_Padding(keyData, resultData);
            Arrays.fill(keyData, (byte) 0);
            Arrays.fill(resultData, (byte) 0);

            // byte[]-->String
            result = new String(srcData, ENCODING);
            return result;
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new CipherBusinessException(Code.SM4_UNCOVER_ERROR);
        }

    }


    /**
     * 加密模式之CBC
     */
    public static byte[] encrypt_Cbc_Padding(byte[] key, byte[] data) throws Exception {
        Cipher cipher = generateCbcCipher(SM4_ALGORITHM_NAME_CBC_PADDING, Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static Cipher generateCbcCipher(String algorithmName, int mode, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
        Key sm4Key = new SecretKeySpec(key, SM4_ALGORITHM_NAME);
        cipher.init(mode, sm4Key, generateIV());
        return cipher;
    }

    /**
     * 生成CBC暗号
     */

    //生成iv
    public static AlgorithmParameters generateIV() throws Exception {
        //iv 为一个 16 字节的数组，这里采用和 iOS 端一样的构造方法，数据全为0
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0x00);
        AlgorithmParameters params = AlgorithmParameters.getInstance(SM4_ALGORITHM_NAME);
        params.init(new IvParameterSpec(iv));
        return params;
    }

    /**
     * 解密
     */
    public static byte[] decrypt_Cbc_Padding(byte[] key, byte[] cipherText) throws Exception {
        Cipher cipher = generateCbcCipher(SM4_ALGORITHM_NAME_CBC_PADDING, Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

}