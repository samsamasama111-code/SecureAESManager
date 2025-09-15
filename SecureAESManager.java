import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class SecureAESCustomKey {
    // AES密钥字节数组
    private final byte[] key;
    //
    private final SecureRandom secureRandom = new SecureRandom();
    // 使用字符数组存储敏感数据
    private static char[] keyChars = "我的超级安全密钥123!@#".toCharArray();
    // 需要加密的原文字符数组
    private static char[] originalTextChars = "我是一个粉刷匠，粉刷本领强"
            .toCharArray();
    // 存储解密结果的字符数组
    private static char[] decryptedChars = null;

    // main方法演示加密和解密
    public static void main(String[] args) {

        try {

            // 创建AES加密器实例
            SecureAESCustomKey aes = new SecureAESCustomKey(keyChars);

            System.out.println("========== 加密 Start ===========");
            // 加密
            String encrypted = aes.encrypt(originalTextChars);
            // 输出密文
            System.out.println("密文: " + encrypted);
            System.out.println("========== 加密 End ===========");

            // 解密
            System.out.println("========== 解密 Start ===========");
            // 密文
            String encryptedStr = "w7TKz+kei4Ows+qgOvmsGHczfUQcA7wZ9f+jvHrqXFpJO4/M1szPaSDyutOeZbPgQn3jK0tQsGc/DyLvLgLP+zPFjw==";
            // 使用安全方法解密到字符数组
            decryptedChars = aes.decryptToChars(encryptedStr);
            System.out.println("明文: " + new String(decryptedChars));
            System.out.println("========== 解密 End ===========");

            // 清除密钥
            aes.clearKey();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 确保所有敏感数据都被清除
            if (keyChars != null)
                Arrays.fill(keyChars, '\0');
            keyChars = null;
            if (originalTextChars != null)
                Arrays.fill(originalTextChars, '\0');
            originalTextChars = null;
            if (decryptedChars != null)
                Arrays.fill(decryptedChars, '\0');
            decryptedChars = null;
            System.gc(); // 建议调用垃圾回收器以尽快清除内存
            System.runFinalization(); // 确保所有对象都被终结
            System.exit(0);
        }
    }

    public SecureAESCustomKey(char[] keyChars) throws Exception {
        // 使用字符数组而不是字符串，以便可以清除内存
        ByteBuffer buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(keyChars));
        byte[] keyBytes = new byte[buffer.remaining()];
        buffer.get(keyBytes);

        // 哈希密钥
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        this.key = sha256.digest(keyBytes);

        // 立即清除临时数组
        Arrays.fill(keyBytes, (byte) 0);
        Arrays.fill(keyChars, '\0');
        buffer.clear(); // 确保 ByteBuffer 被清理
    }

    public String encrypt(char[] plaintextChars) throws Exception {
        // 将字符串转换为字符数组以便后续清理
        ByteBuffer buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(plaintextChars));
        byte[] plaintextBytes = new byte[buffer.remaining()];
        buffer.get(plaintextBytes);

        try {
            // 生成随机IV (12字节用于GCM)
            byte[] iv = new byte[12];
            secureRandom.nextBytes(iv);

            // 创建GCM参数规范
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

            // 创建AES加密器(GCM模式提供认证加密)
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            // 加密数据
            byte[] ciphertext = cipher.doFinal(plaintextBytes);

            // 组合IV和密文
            byte[] encryptedData = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, encryptedData, 0, iv.length);
            System.arraycopy(ciphertext, 0, encryptedData, iv.length, ciphertext.length);

            return Base64.getEncoder().encodeToString(encryptedData);
        } finally {
            // 清除明文数据
            Arrays.fill(plaintextBytes, (byte) 0);
            Arrays.fill(plaintextChars, '\0');
        }
    }

    // 新增方法：返回字符数组而不是字符串，以便调用者可以安全清除
    public char[] decryptToChars(String encryptedData) throws Exception {
        byte[] data = Base64.getDecoder().decode(encryptedData);

        // 提取IV和密文
        byte[] iv = Arrays.copyOfRange(data, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(data, 12, data.length);

        // 创建GCM参数规范
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        // 创建AES解密器
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        // 解密数据
        byte[] decryptedBytes = cipher.doFinal(ciphertext);
        CharBuffer charBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(decryptedBytes));
        char[] decryptedChars = new char[charBuffer.remaining()];
        charBuffer.get(decryptedChars);

        // 清除临时字节数组
        Arrays.fill(decryptedBytes, (byte) 0);

        return decryptedChars;
    }

    // 提供清除密钥的方法
    public void clearKey() {
        if (key != null) {
            Arrays.fill(key, (byte) 0);
        }
    }

}
