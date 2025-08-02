package com.furqan.passpass;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.Base64;

/**
 * Service for storing and retrieving encrypted vault entries (site, username, password)
 */
public class VaultService {
    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int KEY_SIZE = 256;
    private static final int ITERATIONS = 100_000;
    private static final int IV_LENGTH = 16;
    private static final int SALT_LENGTH = 16;

    private final Map<String, List<String>> userVaults = new HashMap<>(); // username -> List<encryptedEntry>
    private final SecureRandom secureRandom = new SecureRandom();

    public void addEntry(String username, String masterPassword, String site, String siteUsername, String sitePassword) throws Exception {
        byte[] salt = generateSalt();
        SecretKeySpec key = deriveKey(masterPassword, salt);
        byte[] iv = generateIV();
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        String entry = site + ":" + siteUsername + ":" + sitePassword;
        byte[] encrypted = cipher.doFinal(entry.getBytes());
        String encryptedEntry = Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(iv) + ":"
                + Base64.getEncoder().encodeToString(encrypted);
        userVaults.computeIfAbsent(username, k -> new ArrayList<>()).add(encryptedEntry);
    }

    public List<String[]> getEntries(String username, String masterPassword) throws Exception {
        List<String> encryptedEntries = userVaults.getOrDefault(username, Collections.emptyList());
        List<String[]> result = new ArrayList<>();
        for (String encryptedEntry : encryptedEntries) {
            String[] parts = encryptedEntry.split(":");
            if (parts.length != 3) continue;
            byte[] salt = Base64.getDecoder().decode(parts[0]);
            byte[] iv = Base64.getDecoder().decode(parts[1]);
            byte[] encrypted = Base64.getDecoder().decode(parts[2]);
            SecretKeySpec key = deriveKey(masterPassword, salt);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            String decrypted = new String(cipher.doFinal(encrypted));
            String[] entryParts = decrypted.split(":", 3);
            if (entryParts.length == 3) {
                result.add(entryParts);
            }
        }
        return result;
    }

    private SecretKeySpec deriveKey(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
