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
    private static final long TIMEOUT_MILLIS = 5 * 60 * 1000; // 5 minutes

    private final Map<String, List<String>> userVaults = new HashMap<>(); // username -> List<encryptedEntry>
    private final SecureRandom secureRandom = new SecureRandom();

    // Timeout mechanism fields
    private transient SecretKeySpec cachedKey = null;
    private transient byte[] cachedSalt = null;
    private transient long lastActivity = 0;
    private transient Timer timeoutTimer = null;

    public void addEntry(String username, String masterPassword, String site, String siteUsername, String sitePassword) throws Exception {
        byte[] salt = generateSalt();
        SecretKeySpec key = getOrCacheKey(masterPassword, salt);
        byte[] iv = generateIV();
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        String entry = site + ":" + siteUsername + ":" + sitePassword;
        byte[] encrypted = cipher.doFinal(entry.getBytes());
        String encryptedEntry = Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(iv) + ":"
                + Base64.getEncoder().encodeToString(encrypted);
        userVaults.computeIfAbsent(username, k -> new ArrayList<>()).add(encryptedEntry);
        updateLastActivity();
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
            SecretKeySpec key = getOrCacheKey(masterPassword, salt);
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            String decrypted = new String(cipher.doFinal(encrypted));
            String[] entryParts = decrypted.split(":", 3);
            if (entryParts.length == 3) {
                result.add(entryParts);
            }
        }
        updateLastActivity();
        return result;
    }
    // Returns cached key if salt matches and not timed out, else derives and caches new key
    private SecretKeySpec getOrCacheKey(String password, byte[] salt) throws Exception {
        long now = System.currentTimeMillis();
        if (cachedKey != null && Arrays.equals(salt, cachedSalt) && (now - lastActivity) < TIMEOUT_MILLIS) {
            updateLastActivity();
            return cachedKey;
        }
        // Derive and cache new key
        cachedKey = deriveKey(password, salt);
        cachedSalt = salt.clone();
        updateLastActivity();
        return cachedKey;
    }

    // Updates last activity and (re)schedules timeout
    private void updateLastActivity() {
        lastActivity = System.currentTimeMillis();
        if (timeoutTimer != null) {
            timeoutTimer.cancel();
        }
        timeoutTimer = new Timer(true);
        timeoutTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                clearCachedKey();
            }
        }, TIMEOUT_MILLIS);
    }

    // Clears the cached AES key from memory
    public void clearCachedKey() {
        if (cachedKey != null) {
            Arrays.fill(cachedKey.getEncoded(), (byte) 0);
        }
        cachedKey = null;
        cachedSalt = null;
        lastActivity = 0;
        if (timeoutTimer != null) {
            timeoutTimer.cancel();
            timeoutTimer = null;
        }
    }

    private SecretKeySpec deriveKey(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Arrays.fill(keyBytes, (byte) 0); // Clear key bytes from memory
        return key;
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    // Call this on logout to clear the cached key immediately
    public void onLogout() {
        clearCachedKey();
    }

    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
