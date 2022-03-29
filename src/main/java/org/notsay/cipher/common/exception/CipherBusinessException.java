package org.notsay.cipher.common.exception;

import org.notsay.cipher.common.enums.Code;

/**
 * @description:
 * @author: dsy
 * @date: 2022/3/29 15:34
 */
public class CipherBusinessException extends RuntimeException{
    private Code code;

    private String msg;

    public CipherBusinessException(Code code) {
        this(code, code.getMsg());
    }

    public CipherBusinessException(Code code, String message) {
        super(message);
        this.code = code;
        msg = message;
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }

    public Code getCode() {
        return code;
    }

    public String getMsg() {
        return msg;
    }
}