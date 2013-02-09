/*Copyright (c) 2013 Roger Brooks http://www.rogerbrooks.us

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.*/
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Arrays;
import java.util.StringTokenizer;

/**
 * A Secure Cookie Protocol
 *
 * A secure cookie protocol based on the white paper by:
 * Alex X. Liu, Jason M. Kovacs - Department of Computer Sciences
 *                                University of Texas at Austin
 *
 * Chin-Tser Huang - Dept. of Computer Science and Engineering
 *                   University of South Carolina
 *
 * Mohamed G. Gouda - Department of Computer Sciences
 *                    The University of Texas at Austin
 * @link http://www.cse.msu.edu/~alexliu/publications/Cookie/cookie.pdf
 *
 * Class written by: Roger Brook
 * @link http://www.rogerbrooks.us
 */
public class SecureCookie {
    private long secondsToExpire = 300;  //five minutes
    private byte[] serverKey;
    private byte[] sessionKey;
    private String userName;

    static BASE64Encoder base64Encoder = new BASE64Encoder();
    static BASE64Decoder base64Decoder = new BASE64Decoder();

    private static final String TOKEN             = "\u0000\u0000";
    private static final String KEY_SCHEME        = "AES";
    private static final String ENCRYPTION_SCHEME = "AES/CBC/PKCS5Padding"  ;
    private static final String HMAC_HASH         = "HmacMD5";
    private static final int  IV_KEY_SIZE         = 16;

    /**
     * Constructor
     * @param serverKey  The secret key set on the server
     * @param sessionKey The ssl session key (Secure Cookie assumes a ssl session)
     * @param userName   The username of the current user, or unique ID
     */
    public SecureCookie(byte[] serverKey, byte[] sessionKey, String userName) {
        this.serverKey = serverKey;
        this.sessionKey = sessionKey;
        this.userName = userName;
    }

    /**
     * Get TTL of the cookie in seconds
     * @return TTL in seconds
     */
    public long getSecondsToExpire() {
        return secondsToExpire;
    }

    /**
     * Set the TTL of the cookie in seconds
     * @param secondsToExpire TTL in seconds
     */
    public void setSecondsToExpire(long secondsToExpire) {
        this.secondsToExpire = secondsToExpire;
    }

    /**
     * Make a secure cookie with the following value
     * @param value The value you would like to store in the cookie
     * @return The value to be sent with the cookie
     */
    public String getSecureCookie(String value) throws Exception {
        String expireTime = Long.toString(this.secondsToExpire + epoch());
        String header     = userName + TOKEN + expireTime;

        byte[] key        = hmac(header.getBytes(), serverKey);
        byte[] auth       = hmac(new String(header + TOKEN + value + TOKEN + base64Encoder.encode(sessionKey)).getBytes(), key);
        byte[] cryptData  = encrypt(value.getBytes(), key);

        return header + TOKEN + base64Encoder.encode(cryptData) + TOKEN + base64Encoder.encode(auth);
    }

    /**
     * Verify the cookie has not been tampered with or expired
     * @param value  The value received back from the cookie
     * @return  Returns null if the cookie is not valid, or the value stored in the cookie
     * @throws IOException
     */
    public String verifySecureCookie(String value) throws Exception {
        StringTokenizer strtok = new StringTokenizer(value, TOKEN);
        String userName      = strtok.nextToken();
        String expireTime    = strtok.nextToken();
        String header        = userName + TOKEN + expireTime;

        byte[] encryptedData = base64Decoder.decodeBuffer(strtok.nextToken());
        byte[] authValue     = base64Decoder.decodeBuffer(strtok.nextToken());
        byte[] key           = hmac(header.getBytes(), serverKey);

        // There will be null chars appended, I assume because of padding for the block cipher, strip these
        // If anyone knows better point it out please.
        String data          = new String(decrypt(encryptedData, key));
        data = data.replaceAll("[\u0000-\u001f]", "");
        byte[] authCheck     = hmac(new String(header + TOKEN + data + TOKEN + base64Encoder.encode(sessionKey)).getBytes(), key);

        if(Long.parseLong(expireTime) > epoch() && Arrays.equals(authValue, authCheck)) {
            return data.toString();
        } else {
            return null;
        }
    }

    /**
     * Create a Hashed-Message-Authentication-Code
     * @link http://en.wikipedia.org/wiki/HMAC
     * @param data Data to be hashed
     * @param key  The key to use
     * @return HMAC hash
     */
    private byte[] hmac(byte[] data, byte[] key) throws Exception {
        try {
            SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_HASH);
            Mac mac = Mac.getInstance(HMAC_HASH);
            mac.init(signingKey);
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }

    /**
     * Wrapper function for doCipher
     * @param data The data to encrypt
     * @param key  The key used to encrypt the data
     * @return The encrypted data
     */
    private byte[] encrypt(byte[] data, byte[] key) throws Exception {
        return doCipher(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * Wrapper function for doCipher
     * @param data The data to decrypt
     * @param key  The key used to decrypt the data
     * @return The decrypted data
     */
    private byte[] decrypt(byte[] data, byte[] key) throws Exception {
        return doCipher(data, key, Cipher.DECRYPT_MODE);
    }

    /**
     * Runs the cipher algorithm against the data
     * @param data The data to run through the cipher
     * @param key  The key to use with the cipher
     * @param mode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE as required
     * @link http://docs.oracle.com/javase/1.4.2/docs/api/javax/crypto/Cipher.html
     * @return The result of the cipher
     */
    private byte[] doCipher(byte[] data, byte[] key, int mode) throws Exception {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, KEY_SCHEME);
            IvParameterSpec ivSpec = new IvParameterSpec(new byte[IV_KEY_SIZE]);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_SCHEME);
            cipher.init(mode, secretKeySpec, ivSpec);
            byte[] rawResult = new byte[cipher.getOutputSize(data.length)];
            int rawLength = cipher.update(data, 0, data.length, rawResult, 0);
            rawLength += cipher.doFinal(rawResult, rawLength);
            return rawResult;
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }

    /**
     * Simple function to return the current epoch in seconds
     * @return The time in seconds since epoch
     */
    private long epoch() {
        return (System.currentTimeMillis() / 1000);
    }
}

/*
 TODOs
 TODO Better Exception handling/input checking
 */
