package org.notsay.cipher.common.util.sm2;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * @description:
 * @author: dsy
 * @date: 2022/4/11 16:43
 */
public class SM2KeyVO {
    BigInteger privateKey;
    ECPoint publicKey;

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public ECPoint getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ECPoint publicKey) {
        this.publicKey = publicKey;
    }

}
