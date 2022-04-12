# dsy-sm-cipher

参考别人方式集合成为加密工具，纯搬运工 参考文档或工具链接：
https://github.com/swhmonster/personal_springboot/blob/master/source_code/spbt/src/main/java/com/walter/spbt/sm/SM2Utils.java

https://npm.runkit.com/sm-crypto

更新记录：

1、新增Sm3加密工具类；新增Sm4加密工具类

2、新增Sm2加密工具类，可以后端与后端加解密，也可以后端加密-前端解密，也可以前端加密-后端解密

注意事项：后端加密后的密文，前端需要去掉前两位的04才可以解密，同理，前端加密的密文后端需要在前面加上04才可以正常解密