/**
 * Copyright@xiaocong.tv 2013
 */
package tv.xiaocong.appstore.client.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


/**
 * @author weijun.ye
 * @version
 * @date 2013-1-29
 */
public class RSACoder {

    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    public static final String PUBLIC_KEY = "RSAPublicKey";
    public static final String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data  加密数据
     * @param privateKey  私钥
     *
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        // 解密由base64编码的私钥
        byte[] keyBytes = decryptBASE64(privateKey);
        // 构造PKCS8EncodedKeySpec对象
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 取私钥匙对象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 用私钥对信息生成数字签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);

        return encryptBASE64(signature.sign());
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data  加密数据
     * @param priKey  私钥
     *
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, PrivateKey priKey) throws Exception {
        // 用私钥对信息生成数字签名
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(data);

        return encryptBASE64(signature.sign());
    }


    /**
     *  用私钥对信息生成数字签名
     *
     * @param partnerId 合作商ID
     * @param service 方法名
     * @param requestData 请求数据
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static String sign(String partnerId, String service, String requestData, String privateKey) throws Exception {
        //partnerId=&service=&requestData=
        StringBuffer sb = new StringBuffer();
        sb.append("partnerId=").append(partnerId);
        sb.append("&service=").append(service);
        sb.append("&requestData=").append(requestData);
        return sign(sb.toString().getBytes(),privateKey);
    }

    /**
     *  用私钥对信息生成数字签名
     *
     * @param partnerId 合作商ID
     * @param service 方法名
     * @param requestData 请求数据
     * @param privateKey 私钥
     * @return
     * @throws Exception
     */
    public static String sign(String partnerId, String service, String requestData, PrivateKey priKey) throws Exception {
        //partnerId=&service=&requestData=
        StringBuffer sb = new StringBuffer();
        sb.append("partnerId=").append(partnerId);
        sb.append("&service=").append(service);
        sb.append("&requestData=").append(requestData);
        return sign(sb.toString().getBytes(),priKey);
    }

    /**
     * 校验数字签名
     *
     * @param data 加密数据
     * @param publicKey 公钥
     * @param sign 数字签名
     *
     * @return 校验成功返回true 失败返回false
     * @throws Exception
     *
     */
    public static boolean verify(byte[] data, String publicKey, String sign)throws Exception {

        // 解密由base64编码的公钥
        byte[] keyBytes = decryptBASE64(publicKey);
        // 构造X509EncodedKeySpec对象
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 取公钥匙对象
        PublicKey pubKey = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);
        // 验证签名是否正常
        return signature.verify(decryptBASE64(sign));
    }

    /**
     * 校验数字签名
     *
     * @param data 加密数据
     * @param publicKey 公钥
     * @param sign 数字签名
     *
     * @return 校验成功返回true 失败返回false
     * @throws Exception
     *
     */
    public static boolean verify(byte[] data, PublicKey pubKey, String sign) throws Exception {

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(pubKey);
        signature.update(data);

        // 验证签名是否正常
        return signature.verify(decryptBASE64(sign));
    }

    public static boolean verify(String partnerId, String service, String requestData,  String publicKey, String sign)throws Exception {
        //partnerId=&service=&requestData=
        StringBuffer sb = new StringBuffer();
        sb.append("partnerId=").append(partnerId);
        sb.append("&service=").append(service);
        sb.append("&requestData=").append(requestData);
        return verify(sb.toString().getBytes(), publicKey, sign);
    }

    public static boolean verify(String partnerId, String service, String requestData, PublicKey pubKey, String sign) throws Exception {
        //partnerId=&service=&requestData=
        StringBuffer sb = new StringBuffer();
        sb.append("partnerId=").append(partnerId);
        sb.append("&service=").append(service);
        sb.append("&requestData=").append(requestData);
        return verify(sb.toString().getBytes(), pubKey, sign);
    }

    /**
     * 解密<br>
     * 用私钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key)throws Exception {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decryptResult = new byte[] {};
        for(int i = 0; i < data.length; i += 128) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 128));
            decryptResult = ArrayUtils.addAll(decryptResult, doFinal);
        }
        return decryptResult;
    }




    /**
     * 解密<br>
     * 用私钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, Key privateKey)throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decryptResult = new byte[] {};
        for(int i = 0; i < data.length; i += 128) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 128));
            decryptResult = ArrayUtils.addAll(decryptResult, doFinal);
        }
        return decryptResult;
    }

    /**
     * 解密<br>
     * 用公钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, String key)throws Exception {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] decryptResult = new byte[] {};
        for(int i = 0; i < data.length; i += 128) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 128));
            decryptResult = ArrayUtils.addAll(decryptResult, doFinal);
        }
        return decryptResult;
    }

    /**
     * 解密<br>
     * 用公钥解密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] data, Key publicKey)throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] decryptResult = new byte[] {};
        for(int i = 0; i < data.length; i += 128) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 128));
            decryptResult = ArrayUtils.addAll(decryptResult, doFinal);
        }
        return decryptResult;
    }

    /**
     * 加密<br>
     * 用公钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
        // 对公钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptResult = new byte[] {};
        for (int i = 0; i < data.length; i += 100) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 100));
            encryptResult = ArrayUtils.addAll(encryptResult, doFinal);
        }
        return encryptResult;
    }

    /**
     * 加密<br>
     * 用公钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data,  Key publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptResult = new byte[] {};
        for (int i = 0; i < data.length; i += 100) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 100));
            encryptResult = ArrayUtils.addAll(encryptResult, doFinal);
        }
        return encryptResult;
    }

    /**
     * 加密<br>
     * 用私钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String key)throws Exception {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] encryptResult = new byte[] {};
        for (int i = 0; i < data.length; i += 100) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 100));
            encryptResult = ArrayUtils.addAll(encryptResult, doFinal);
        }
        return encryptResult;
    }

    /**
     * 加密<br>
     * 用私钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, Key privateKey)throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] encryptResult = new byte[] {};
        for (int i = 0; i < data.length; i += 100) {
            byte[] doFinal = cipher.doFinal(ArrayUtils.subarray(data, i, i + 100));
            encryptResult = ArrayUtils.addAll(encryptResult, doFinal);
        }
        return encryptResult;
    }

    /**
     * 取得私钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap)throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);

        return encryptBASE64(key.getEncoded());
    }

    /**
     * 取得公钥
     *
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);

        return encryptBASE64(key.getEncoded());
    }

    /**
     * 生成密钥对
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> generateKey() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024);

        KeyPair keyPair = keyPairGen.generateKeyPair();

        // 公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        // 私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        Map<String, Object> keyMap = new HashMap<String, Object>(2);

        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /**
     * BASE64解密
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    /**
     * BASE64加密
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptBASE64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

    /**
     * 读取公钥
     * @param publicFilePath 公钥文件
     * @param fileType 文件类型
     * @return
     */
    public static PublicKey getPublicKeyFromFile(String publicFilePath,int fileType) throws Exception{
        String publicKeyStr = null;

        switch (fileType) {
            case 0:
                publicKeyStr = getKeyStrFromTextFile(publicFilePath);
                break;
            case 1:
                publicKeyStr = getKeyStrFromPemFile(publicFilePath);
                break;
            default:
                publicKeyStr = getKeyStrFromTextFile(publicFilePath);
        }
        byte[] publickeyBytes = Base64.decode(publicKeyStr);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publickeyBytes);
        PublicKey publicKey = kf.generatePublic(keySpec);
        return publicKey;
    }

    /**
     * 读取私钥
     * @param privateFilePath  私钥文件
     * @param fileType 文件类型
     * @return
     */
    public static PrivateKey getPrivateKeyFromFile(String privateFilePath,int fileType) throws Exception{
        String privateKeyStr = null;

        switch (fileType) {
            case 0:
                privateKeyStr = getKeyStrFromTextFile(privateFilePath);
                break;
            case 1:
                privateKeyStr = getKeyStrFromPemFile(privateFilePath);
                break;
            default:
                privateKeyStr = getKeyStrFromTextFile(privateFilePath);
        }
        byte[] privateKeyBytes = Base64.decode(privateKeyStr);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
                privateKeyBytes);
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 从pem文件读取私钥
     * @param pemFilePath 文件路径
     * @return
     */
    public static String getKeyStrFromPemFile(String pemFilePath) throws Exception{
        BufferedReader br = new BufferedReader(new FileReader(pemFilePath));
        String s = br.readLine();
        StringBuffer keyBuf = new StringBuffer();
        s = br.readLine();
        while (s.charAt(0) != '-') {
            keyBuf.append(s + "\r");
            s = br.readLine();
        }
        return keyBuf.toString();
    }

    /**
     * 从txt文件读取私钥
     * @param filePath 文件路径
     * @return
     * @throws Exception
     */
    public static String getKeyStrFromTextFile(String filePath) throws Exception {
        File file = new File(filePath);
        BufferedReader bf = new BufferedReader(new FileReader(file));
        String content = "";
        StringBuilder stringBuilder = new StringBuilder();
        while (stringBuilder != null) {
            content = bf.readLine();
            if (StringUtils.isEmpty(content)) {
                break;
            }
            stringBuilder.append(content);
        }
        bf.close();
        return stringBuilder.toString();
    }




}
