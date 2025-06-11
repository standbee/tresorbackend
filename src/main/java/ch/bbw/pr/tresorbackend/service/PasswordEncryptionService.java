package ch.bbw.pr.tresorbackend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * PasswordEncryptionService
 *
 * @author s.beere
 */

@Service
public class PasswordEncryptionService {
    private final String pepper;

    public PasswordEncryptionService(@Value("${security.pepper}") String pepper) { // get the 'pepper' from application.properties
        this.pepper = pepper;
    }


    // SecureRandom to generate salt
    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    // resource: https://www.baeldung.com/java-password-hashing
    // see docs for more on hashing algorithms and practices
    // PBKDF2 for password hashing
    public String hashPassword(String password, byte[] salt) {
        // combine password with pepper
        String passwordWithPepper = password + pepper;
        try {
            // hash password with salt and pepper
            PBEKeySpec spec = new PBEKeySpec(passwordWithPepper.toCharArray(), salt, 10000, 256); // 256-bit hash length
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hashedPassword = factory.generateSecret(spec).getEncoded();
            // salt and pepper hashed password combined to store in the database
            return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hashedPassword);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean doesPasswordMatch(String loginPassword, String storedPassword) {
        try {
            String[] parts = storedPassword.split(":");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Stored password must be in 'salt:hash' format");
            }

            byte[] salt = Base64.getDecoder().decode(parts[0]);
            String storedHash = parts[1];

            // Recreate the hashed password from the login input
            String recomputedHash = hashPassword(loginPassword, salt);

            // Extract hash part from recomputed value
            String recomputedHashOnly = recomputedHash.split(":")[1];

            return MessageDigest.isEqual(
                    Base64.getDecoder().decode(recomputedHashOnly),
                    Base64.getDecoder().decode(storedHash)
            );

        } catch (Exception e) {
            throw new RuntimeException("Password matching failed", e);
        }
    }


//    public boolean doesPasswordMatch(String password, String hashedPassword){
//        return BCrypt.checkpw(password, hashedPassword);
//    }
//
//    public String hashPassword(String password, String salt) {
//        String pepperedPassword = password + pepper;
//        return BCrypt.hashpw(pepperedPassword, salt);
//    }
//
//    public String generateSalt() {
//        return BCrypt.gensalt();
//    }


//    public boolean doesPasswordMatch(String loginPassword, String hashedPassword) {
//
//        String[] parts = hashedPassword.split(":");
//        if (parts.length != 2) {
//            throw new IllegalArgumentException("Invalid hashed password format");
//        }
//
//        String salt = parts[0];
//        String storedHash = parts[1];
//        System.out.println(storedHash);
//
////        String salt = hashedPassword.substring(0, hashedPassword.indexOf(":"));
////        String storedHash = hashedPassword.substring(hashedPassword.indexOf(":"), 0);
//
//        String loginComparePassword = hashPassword(loginPassword, salt.getBytes());
//
//        try {
//            if (Objects.equals(loginComparePassword, storedHash)) {
//                return true;
//            }
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//        return false;
//    }

//    public boolean doesPasswordMatch(String loginPassword, String hashedPassword) {
//        String[] parts = hashedPassword.split(":");
//        if (parts.length != 2) {
//            throw new IllegalArgumentException("Invalid hashed password format");
//        }
//
//        String salt = parts[0];
//        String storedHash = parts[1];
//
//        try {
//            String calculatedHash = hashPassword(loginPassword, salt.getBytes());
//            return Objects.equals(calculatedHash, storedHash);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//    }


}