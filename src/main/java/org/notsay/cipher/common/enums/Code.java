package org.notsay.cipher.common.enums;

/**
 * @description:
 * @author: dsy
 * @date: 2022/3/29 15:33
 */
public enum Code {

    //错误码枚举
    SUCCESS(0, "成功"),
    FAILED(1, "失败"),
    SYSTEM_BUSY(999999, "系统繁忙，请稍后再试"),


    SM4_PROTECT_ERROR(1001, "SM4加密失败"),

    SM4_UNCOVER_ERROR(1002, "SM4解密失败"),

    SM4_GEN_KEY_ERROR(1003, "生成SM4秘钥失败"),

    SM3_PROTECT_ERROR(2001, "SM3签名失败"),

    SM3_VERIFY_ERROR(2002, "SM3验签失败"),

    ;

    private int code;

    private String message;

    Code(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMsg() {
        return message;
    }
}