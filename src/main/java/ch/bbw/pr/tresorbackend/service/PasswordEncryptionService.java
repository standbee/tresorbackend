package ch.bbw.pr.tresorbackend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

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

    public String hashPassword(String password) throws Exception {
        byte[] salt = generateSalt();

        String passwordWithPepper = password + pepper;

        // hash password with salt and pepper
        byte[] hashedPassword = hashWithPBKDF2(passwordWithPepper.toCharArray(), salt);

        // salt and hashed password combined to store in the database
        return Base64.getEncoder().encodeToString(salt) + ":" + Base64.getEncoder().encodeToString(hashedPassword);
    }


    // SecureRandom to generate salt
    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    // resource: https://www.baeldung.com/java-password-hashing
    // see docs for more on hashing algorithms and practices
    // PBKDF2 for password hashing
    private byte[] hashWithPBKDF2(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 10000, 256); // 256-bit hash length
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }
}
