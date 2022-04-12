package org.notsay.cipher.common.util.sm2;


import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.notsay.cipher.common.enums.Code;
import org.notsay.cipher.common.exception.CipherBusinessException;
import org.notsay.cipher.common.util.SelfByteUtils;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * @description:
 * @author: dsy
 * @date: 2022/4/11 16:43
 */
public class Sm2Utils {
    private static final Logger log = Logger.getLogger(Sm2Utils.class.getName());

    /**
     * 数据加密
     *
     * @param publicKey
     * @param data
     * @return
     */
    public static String protectMsg(String publicKey, String data) {
        try {
            if (publicKey == null || "".equals(publicKey)) {
                return null;
            }

            if (data == null || "".equals(data)) {
                return null;
            }

            byte[] source = data.getBytes();

            Cipher cipher = new Cipher();
            SM2 sm2 = SM2.Instance();
            ECPoint userKey = sm2.ecc_curve.decodePoint(SelfByteUtils.hexToByte(publicKey));

            ECPoint c1 = cipher.Init_enc(sm2, userKey);
            cipher.Encrypt(source);
            byte[] c3 = new byte[32];
            cipher.Dofinal(c3);
            return SelfByteUtils.byteToHex(c1.getEncoded(false)) + SelfByteUtils.byteToHex(source) + SelfByteUtils.byteToHex(c3);
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new CipherBusinessException(Code.SM2_PROTECT_ERROR);
        }
    }

    /**
     * 数据解密 String
     * 前端解密参考：https://npm.runkit.com/sm-crypto
     * 注意：后端加密--前端解密方式下，前端需要将密文的前两位(04)去掉
     */
    public static String uncoverMsg(String privateKey, String encryptedData) {
        if (privateKey == null || "".equals(privateKey)) {
            return null;
        }

        if (encryptedData == null || "".equals(encryptedData)) {
            return null;
        }
        return uncoverMsg(SelfByteUtils.hexToByte(privateKey), SelfByteUtils.hexToByte(encryptedData));
    }


    /**
     * 数据解密 byte[]
     */
    public static String uncoverMsg(byte[] privateKey, byte[] encryptedData) {
        try {
            if (privateKey == null || privateKey.length == 0) {
                return null;
            }

            if (encryptedData == null || encryptedData.length == 0) {
                return null;
            }
            //加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
            String data = SelfByteUtils.byteToHex(encryptedData);
            /* 分解加密字串
             * （C1 = C1标志位2位 + C1实体部分128位 = 130）
             * （C3 = C3实体部分64位  = 64）
             * （C2 = encryptedData.length * 2 - C1长度  - C2长度）
             */
            byte[] c1Bytes = SelfByteUtils.hexToByte(data.substring(0, 130));
            int c2Len = encryptedData.length - 97;
            byte[] c2 = SelfByteUtils.hexToByte(data.substring(130, 130 + 2 * c2Len));
            byte[] c3 = SelfByteUtils.hexToByte(data.substring(130 + 2 * c2Len, 194 + 2 * c2Len));

            SM2 sm2 = SM2.Instance();
            BigInteger userD = new BigInteger(1, privateKey);

            //通过C1实体字节来生成ECPoint
            ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
            Cipher cipher = new Cipher();
            cipher.Init_dec(userD, c1);
            cipher.Decrypt(c2);
            cipher.Dofinal(c3);

            //返回解密结果
            return new String(c2);
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new CipherBusinessException(Code.SM2_UNCOVER_ERROR);
        }

    }

    /**
     * 生成随机秘钥对
     */
    public static void generateKeyPair() {
        try {
            SM2 sm2 = SM2.Instance();
            AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
            ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
            ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
            BigInteger privateKey = ecpriv.getD();
            ECPoint publicKey = ecpub.getQ();

            log.info("publicKey: " + SelfByteUtils.byteToHex(publicKey.getEncoded()));
            log.info("privateKey: " + SelfByteUtils.byteToHex(privateKey.toByteArray()));
        } catch (Exception e) {
            log.info(e.getMessage());
            throw new CipherBusinessException(Code.SM2_GEN_KEY_ERROR);
        }

    }

}