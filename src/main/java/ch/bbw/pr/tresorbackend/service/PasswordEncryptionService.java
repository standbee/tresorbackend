package ch.bbw.pr.tresorbackend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
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


    public boolean doesPasswordMatch(String loginPassword, String hashedPassword) {

        String salt = hashedPassword.substring(0, hashedPassword.indexOf(":"));

        try {
            if (Objects.equals(hashPassword(loginPassword, salt.getBytes()), hashedPassword)) {
                return true;
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return false;
    }

}