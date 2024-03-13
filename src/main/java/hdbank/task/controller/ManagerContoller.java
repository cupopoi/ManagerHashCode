package hdbank.task.controller;

import hdbank.task.model.Input;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

@RestController
@RequestMapping("/api/v1/")
public class ManagerContoller {
    @PostMapping("/sha256")
    public String SHA256(@RequestBody Input input) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(input.getInput().getBytes());
            StringBuilder hexBuilder = new StringBuilder();
            Formatter formatter = new Formatter(hexBuilder);
            for (byte b : hash) {
                formatter.format("%02x", b);
            }
            String hashHex = hexBuilder.toString();
            return hashHex;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "Lỗi";
    }

    @PostMapping("/hmac-sha256")
    public String HMACSHA256(@RequestBody Input input) {
        String key = "secret";
        try {
            Mac hmacSHA256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
            hmacSHA256.init(secretKey);
            byte[] hash = hmacSHA256.doFinal(input.getInput().getBytes());
            StringBuilder hexBuilder = new StringBuilder();
            Formatter formatter = new Formatter(hexBuilder);
            for (byte b : hash) {
                formatter.format("%02x", b);
            }
            String hashHex = hexBuilder.toString();
            return hashHex;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return "Lỗi";
    }

    @PostMapping("/md5")
    public String MD5(@RequestBody Input input) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] hash = md5.digest(input.getInput().getBytes());
            BigInteger number = new BigInteger(1, hash);
            String md5Hash = number.toString(16);
            return md5Hash;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "Lỗi";
    }

    @PostMapping("/sha1")
    public String SHA1(@RequestBody Input input) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] hash = sha1.digest(input.getInput().getBytes());
            StringBuilder hexBuilder = new StringBuilder();
            Formatter formatter = new Formatter(hexBuilder);
            for (byte b : hash) {
                formatter.format("%02x", b);
            }
            String hashHex = hexBuilder.toString();
            return hashHex;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "Lỗi";
    }
}
