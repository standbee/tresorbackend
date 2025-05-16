package ch.bbw.pr.tresorbackend.util;

import jakarta.validation.constraints.NotEmpty;

import javax.crypto.*;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

/**
 * EncryptUtil
 * Used to encrypt content.
 * Not implemented yet.
 *
 * @author Peter Rutschmann
 */
public class EncryptUtil {

    public EncryptUtil(@NotEmpty(message = "encryption password id is required.") String encryptPassword) {

    }

    public static String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    public static byte[] generateInitVector() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public static String encrypt(String data, String password, String salt, byte[] iv) {
        try {

            SecretKey secretKey = getKeyFromPassword(password, salt);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

            // encrypt the data
            byte[] encryptedBytes = cipher.doFinal(data.getBytes());

            // combine init vector and encrypted data
            byte[] ivAndEncryptedBytes = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, ivAndEncryptedBytes, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, ivAndEncryptedBytes, iv.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(ivAndEncryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String encryptedData, String password, String salt, byte[] iv) {
        try {

            SecretKey secretKey = getKeyFromPassword(password, salt);
            byte[] ivAndEncryptedBytes = Base64.getDecoder().decode(encryptedData);

            byte[] encryptedBytes = new byte[ivAndEncryptedBytes.length - 16];
            System.arraycopy(ivAndEncryptedBytes, 0, iv, 0, iv.length);
            System.arraycopy(ivAndEncryptedBytes, iv.length, encryptedBytes, 0, encryptedBytes.length);

            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            // decrypt the data
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static SecretKey getKeyFromPassword(String password, String salt) {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
            SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

            return secret;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}

