package org.notsay.cipher.common.util.sm2;


import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @description:
 * @author: dsy
 * @date: 2022/4/11 16:43
 */
public class SM2 {

    //国密参数
    public static String[] ecc_param = {
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
    };

    public static SM2 Instance() {
        return new SM2();
    }

    public final BigInteger ecc_p;
    public final BigInteger ecc_a;
    public final BigInteger ecc_b;
    public final BigInteger ecc_n;
    public final BigInteger ecc_gx;
    public final BigInteger ecc_gy;
    public final ECCurve ecc_curve;
    public final ECPoint ecc_point_g;
    public final ECDomainParameters ecc_bc_spec;
    public final ECKeyPairGenerator ecc_key_pair_generator;
    public final ECFieldElement ecc_gx_fieldelement;
    public final ECFieldElement ecc_gy_fieldelement;

    public SM2() {
        ecc_p = new BigInteger(ecc_param[0], 16);
        ecc_a = new BigInteger(ecc_param[1], 16);
        ecc_b = new BigInteger(ecc_param[2], 16);
        ecc_n = new BigInteger(ecc_param[3], 16);
        ecc_gx = new BigInteger(ecc_param[4], 16);
        ecc_gy = new BigInteger(ecc_param[5], 16);

        ecc_gx_fieldelement = new Fp(ecc_p, ecc_gx);
        ecc_gy_fieldelement = new Fp(ecc_p, ecc_gy);

        ecc_curve = new ECCurve.Fp(ecc_p, ecc_a, ecc_b);
        ecc_point_g = new ECPoint.Fp(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);

        ecc_bc_spec = new ECDomainParameters(ecc_curve, ecc_point_g, ecc_n);

        ECKeyGenerationParameters ecc_ecgenparam;
        ecc_ecgenparam = new ECKeyGenerationParameters(ecc_bc_spec, new SecureRandom());

        ecc_key_pair_generator = new ECKeyPairGenerator();
        ecc_key_pair_generator.init(ecc_ecgenparam);
    }
}
