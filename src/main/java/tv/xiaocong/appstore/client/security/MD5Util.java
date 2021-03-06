/**
 * Copyright@xiaocong.tv 2012
 */
package tv.xiaocong.appstore.client.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.security.MessageDigest;


/**
 * MD5
 * @author weijun.ye
 * @version 
 * @date 2012-4-26
 */
public class MD5Util {
    
    private static Log log = LogFactory.getLog(MD5Util.class);
    
    private static final char hexDigits[] = 
            { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    
    private MD5Util() {
        //ignore
    }
    
    public static String getMD5(String source) throws Exception {
        
        if (null == source) return source;
        
        String s = null;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(source.getBytes("UTF-8"));
            byte tmp[] = md.digest();
            char str[] = new char[16 * 2];
            int k = 0;
            for (int i = 0; i < 16; i++) {
                byte byte0 = tmp[i];
                str[k++] = hexDigits[byte0 >>> 4 & 0xf];
                str[k++] = hexDigits[byte0 & 0xf];
            }
            s = new String(str);

        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new Exception(e.getMessage(), e);
        }
        
        return s;
    }
    
    public static String sign(String content, String key) throws Exception{
    	String signData = content + "&" + key;
    	return getMD5(signData);
    }
    
    public static boolean checkSign(String content,String sign, String key) throws Exception{
    	String signData = sign(content, key);
    	return signData.equals(sign);
    }
      
    
}