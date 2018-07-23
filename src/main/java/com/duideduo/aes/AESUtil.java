package com.duideduo.aes;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * 功能描述：AES 加密解密
 * Created by YQ on 2017/10/13.
 */

public class AESUtil {
    private static final String KEY_ALGORITHM = "AES";
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";//加密算法

    //加密
    public static byte[] encode(String stringToEncode, String keyString) throws NullPointerException {
        if(keyString.length() != 0 && keyString != null) {
            if(stringToEncode.length() != 0 && stringToEncode != null) {
                try {
                    SecretKeySpec var14 = getKey(keyString);
                    byte[] clearText = stringToEncode.getBytes("UTF8");
                    byte[] iv = new byte[16];
                    Arrays.fill(iv, (byte) 0);
                    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                    Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
                    cipher.init(Cipher.ENCRYPT_MODE, var14, ivParameterSpec);
                    return cipher.doFinal(clearText);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                throw new NullPointerException("Please give text");
            }
        } else {
            throw new NullPointerException("Please give Password");
        }
        return null;
    }

    //解密
    public static byte[] decode(byte[] param, String keyString) throws NullPointerException {
        if(keyString.length() != 0 && keyString != null) {
            try {
                SecretKeySpec var15 = getKey(keyString);
                byte[] iv = new byte[16];
                Arrays.fill(iv, (byte) 0);
                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                byte[] encrypedPwdBytes = param;
                Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
                cipher.init(Cipher.DECRYPT_MODE, var15, ivParameterSpec);
                byte[] decrypedValueBytes = cipher.doFinal(encrypedPwdBytes);
                return decrypedValueBytes;
            } catch (Exception e) {
                e.printStackTrace();
            }

        } else {
            throw new NullPointerException("Please give Password");
        }
        return null;
    }

    private static SecretKeySpec getKey(String keyString) throws UnsupportedEncodingException {
        short keyLength = 256;
        byte[] keyBytes = new byte[keyLength / 8];
        Arrays.fill(keyBytes, (byte) 0);
        byte[] passwordBytes = keyString.getBytes("UTF-8");
        int length = passwordBytes.length < keyBytes.length?passwordBytes.length:keyBytes.length;
        System.arraycopy(passwordBytes, 0, keyBytes, 0, length);
        SecretKeySpec key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        return key;
    }

    public static void main(String[] args){
        byte[] a = AESUtil.encode("victorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictorvictor","jjvapbcvwjgazdknftcszjkgimtghaye");
        System.out.println(Base64.getEncoder().encodeToString(a));


        System.out.println(new String(AESUtil.decode(Base64.getDecoder().decode("aSCJKZnBpiCWo679Nad7pUP24OVPaKephJaQnZ+9qvZBlTV3s9+/J1PsZ08g9RAHLfbwTxXM1G+K4jz0arJL3LQsBspfJSA4yxG6lZoLgQGMDIStdAINyi8QgMAbera03yOa7y/bCCMwaLw7cA9zTd+r17IKolr2y0BQtAPbv3bRMYQUtQyUrhyAwQi4K5XNiaXKxoejp/OM3tYGsy5VZjJFicrwqwVW78xJDloZ/A8ukuTW7n5tWy4DNfTe3yhoyNTq3G7+xJ710XXu68wPPQ9nrZ17N+n3G5VVpxwqoAu43LrY4VJ3tiljkReCBoskJN3VltCD6/TstPWv2MIjsdJcnTLcNkCh0FUJKqAzhBOCydJMSlQLmjwE58H6XZI5ycYLWNSKtjHPkpXsy/7i+2DOqbVlyVvQ7y2iDOH0txRywz7BmHFRf79q2BVI0u6e6kClIpZDID+LVbI2ah8K3JU542xD/y8p+M/FvTTLzRCRCMIfWzvyz0Vup+g7W6uTfFRTqL+7BkmcBd5ttagwi2VYPp0pfVYfZpnrJJNHSd5fKf5yY7mzGZMOUhUNJeKyQC6VVH5Hky66vqFKCivdU4ibYhUvIUtwjNDWlAKMrHHkK9AjGQb6dCnfg1QT662sdYKHCBqcBlzL8jGOhXwvuOR4CIIuN3kCxtJGgB7dU4jsgTcwUqqb3Kx9SsuvghJJ2VZoFfM0mbrO9p2M8m2CVJ6+itGJ0LGbdkEENReM5UG6AJvHfWFq2tgITbNwQsAT92RzRRp34Pvpe2zZBzLNIYu72C7Mh85H/cFSSjV+udcqlCB1NClmXgZOD7GPLKdi9j32iJkR5GqgPJtFl8AjrmOzz4mR8yRCaNb7ZO4O4SihxBsfnk6q4uTZuB2PYEzPyROkBEbCpVuVHxiHnoyem/l9fHSZS5Cd0TINXyqWkxvbr/XldZmaJ6XlrJLnDhMbsb+J0jBrcyqS9x0zIijbDI1Mw3Z6vHvgYVfIOBkfotGbDHeFLO+NAwbr9aMgvEC8ektdcXojg9/5RPEyNgsN2KTKYf9d7PjUfUJI4wHtuL83GJtoJ2vapklLBsBp8bo+2WzvgIAROtZbhFgvISqwnnhJRl3nMff71KenXd2N7RI="),"jjvapbcvwjgazdknftcszjkgimtghaye")));
    }

}
