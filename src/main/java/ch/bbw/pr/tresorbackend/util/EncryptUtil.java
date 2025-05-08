package ch.bbw.pr.tresorbackend.util;

import jakarta.validation.constraints.NotEmpty;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private static byte[] generateInitVector() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public static String encrypt(String data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        SecretKey secretKey = generateKey();
        byte[] iv = generateInitVector();
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
    }

    public static String decrypt(String encryptedData, SecretKey secretKey) throws Exception {
        byte[] ivAndEncryptedBytes = Base64.getDecoder().decode(encryptedData);

        byte[] iv = new byte[16];
        byte[] encryptedBytes = new byte[ivAndEncryptedBytes.length - 16];
        System.arraycopy(ivAndEncryptedBytes, 0, iv, 0, iv.length);
        System.arraycopy(ivAndEncryptedBytes, iv.length, encryptedBytes, 0, encryptedBytes.length);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        // decrypt the data
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }
}

