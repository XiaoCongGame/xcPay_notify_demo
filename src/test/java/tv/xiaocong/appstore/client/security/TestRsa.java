package tv.xiaocong.appstore.client.security;

import tv.xiaocong.appstore.client.config.PartnerConfig;

import java.net.URLEncoder;

/**
 * @author weiwei.huang
 * @email hww@xiaocong.tv
 * @date 2014/5/12 0012
 */
public class TestRsa {

    public static void main(String[] args) throws Exception {
        String pubKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPRvLx9zjOKPNSOVY1V3qaNQ13VWRfiEeHwQ6a7apWeyKcrYCWsmiSCQRCdd8TXNHzLobLPLR/A0mF8J895l7qVW8Q1xH+F5eH78AOVFWnZsjJiAMIxnKQlX13iCN7pBOyJKoDMhGCdGoJT1bEGDxqddw6QRARYL0jkIqTvoSa6wIDAQAB";
        String priKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAM9G8vH3OM4o81I5VjVXepo1DXdVZF+IR4fBDprtqlZ7IpytgJayaJIJBEJ13xNc0fMuhss8tH8DSYXwnz3mXupVbxDXEf4Xl4fvwA5UVadmyMmIAwjGcpCVfXeII3ukE7IkqgMyEYJ0aglPVsQYPGp13DpBEBFgvSOQipO+hJrrAgMBAAECgYEAut4v8Mz9PX/Vve9LNVPkiFoEBe3KTAZE1rLKRAq4YrcogTA6maHGfMH8QR6bOo2YCjGL/HaCE3AXPNWt+tRSBDmbZ6qoM59gMkLTklSAjvzRetmSoO4NrsCn2OXaXDPuGfHdfqY0lsZRzpM6lztDQ50AwOo1JXgvhCgOYW4FugECQQDyInaPqFQ0WGtGhSE+ek8YXqHYtDMnfyvUchz8bq4/4reHUHUHwZHAFEE5wjavECPlF91qLZdyR3EYHfRS2nzBAkEA2yV/cPTS4MBp0vS2UXstDxEgM6kM1dhIs7SRwXiVqVVDMraJCVn89l1Z+W3knRqaRjlFYJt0RpW9vNHdkZbGqwJBAOzUQozOgtXUKdEHA/YdIWHfpYPU9TfLji40Ex/gjfSUpxfl3SHh9dIevZFl4aCnM8Su6/UfdMLlF7wUCFZFt8ECQEeO/wZLa3CoY+XWspH4vsXkubckxGQvs826cL3UOkqI5OByalz7XXa1FOQ11ijWvvmfSeA54sYJr2MwxED+EvECQDYizqnd1M5s1iO/PAIpVmb8fJGQwdKqENxP+UAzkB9dmj4DKsEjeDO3Cgurz+S+Tcz3/LpSvhnPVjSQVSKM+70=";
        // 产生签名
        String data = PartnerConfig.PARTNER_ID+"&"+PartnerConfig.PKG_NAME+"&10&10";


        String sign = RSACoder.sign(data.getBytes(), priKey);
        System.out.println("签名:" + sign);

        System.out.println(URLEncoder.encode(sign,"utf8"));
        System.out.println("================");
        boolean result = RSACoder.verify(data.getBytes(), pubKey, sign);
        System.out.println("验签:" + result);
    }
}
