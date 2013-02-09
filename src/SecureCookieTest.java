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
import org.junit.Test;

import static org.junit.Assert.assertEquals;


public class SecureCookieTest {
    /* This is a complete functional test that covers the entire
     * system.
     */
    @Test
    public void testVerifySecureCookie() throws Exception {

        SecureCookie cookie = new SecureCookie("F-E8JHTyP6h!ZyCP!GkG".getBytes(),
                                               "pup_DrZexstPxvPr@jqY-_af^Sfh~GP@".getBytes(),
                                               "secureCookieProtocol123");

        String testData = "this is some test data set to the cookie with a really long string";
        String value = cookie.getSecureCookie(testData);

        assertEquals(testData, cookie.verifySecureCookie(value));
    }

    @Test
    public void testExpiredCookieFails() throws Exception {
        SecureCookie cookie = new SecureCookie("F-E8JHTyP6h!ZyCP!GkG".getBytes(),
                "pup_DrZexstPxvPr@jqY-_af^Sfh~GP@".getBytes(),
                "secureCookieProtocol123");

        //Set negative time so it will be expired right away
        cookie.setSecondsToExpire(-100);

        String testData = "this is some test data set to the cookie with a really long string";
        String value = cookie.getSecureCookie(testData);

        assertEquals(null, cookie.verifySecureCookie(value));
    }
}
