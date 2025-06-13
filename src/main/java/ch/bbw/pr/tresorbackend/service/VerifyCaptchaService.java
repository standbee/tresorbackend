package ch.bbw.pr.tresorbackend.service;

import org.springframework.stereotype.Service;

import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;


@Service
public class VerifyCaptchaService {

    public boolean isCapchaValid(String token) {
        try {
            String secret = "DEIN_SECRET_KEY";
            String url = "https://www.google.com/recaptcha/api/siteverify";
            String params = "secret=" + secret + "&response=" + token;

            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.getOutputStream().write(params.getBytes(StandardCharsets.UTF_8));

            Scanner scanner = new Scanner(conn.getInputStream());
            String response = scanner.useDelimiter("\\A").next();
            scanner.close();

            return response.contains("\"success\": true");
        } catch (Exception e) {
            return false;
        }
    }
}