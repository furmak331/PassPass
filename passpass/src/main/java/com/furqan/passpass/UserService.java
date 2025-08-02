package com.furqan.passpass;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Service class for managing users and password operations
 */
public class UserService {
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int SALT_LENGTH = 16; // 128 bits
    private static final int HASH_LENGTH = 32; // 256 bits
    private static final int ITERATIONS = 100000; // OWASP recommended minimum
    
    private final Map<String, User> users;
    private final SecureRandom secureRandom;
    
    /**
     * Constructor for UserService
     */
    public UserService() {
        this.users = new HashMap<>();
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * Register a new user with username and password
     * @param username The username
     * @param password The plain text password
     * @return true if registration successful, false if username already exists
     * @throws RuntimeException if password hashing fails
     */
    public boolean registerUser(String username, String password) {
        if (users.containsKey(username)) {
            return false;
        }
        
        try {
            byte[] salt = generateSalt();
            byte[] hashedPassword = hashPassword(password, salt);
            
            User user = new User(username, hashedPassword, salt);
            users.put(username, user);
            return true;
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash password during registration", e);
        }
    }
    
    /**
     * Authenticate a user with username and password
     * @param username The username
     * @param password The plain text password
     * @return true if authentication successful, false otherwise
     */
    public boolean authenticateUser(String username, String password) {
        User user = users.get(username);
        if (user == null) {
            return false;
        }
        
        try {
            byte[] hashedInput = hashPassword(password, user.getSalt());
            return Arrays.equals(hashedInput, user.getHashedPassword());
        } catch (Exception e) {
            // Log the error in a real application
            return false;
        }
    }
    
    /**
     * Login a user with username and password
     * @param username The username
     * @param password The plain text password
     * @return true if login successful, false otherwise
     */
    public boolean loginUser(String username, String password) {
        User user = users.get(username);
        if (user == null) {
            return false;
        }
        
        try {
            byte[] hashedInput = hashPassword(password, user.getSalt());
            return Arrays.equals(hashedInput, user.getHashedPassword());
        } catch (Exception e) {
            // Log the error in a real application
            return false;
        }
    }
    
    /**
     * Check if a username exists
     * @param username The username to check
     * @return true if username exists, false otherwise
     */
    public boolean userExists(String username) {
        return users.containsKey(username);
    }
    
    /**
     * Get a user by username
     * @param username The username
     * @return User object or null if not found
     */
    public User getUser(String username) {
        return users.get(username);
    }
    
    /**
     * Get the number of registered users
     * @return number of users
     */
    public int getUserCount() {
        return users.size();
    }
    
    /**
     * Generate a random salt
     * @return byte array containing the salt
     */
    private byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }
    
    /**
     * Hash a password using PBKDF2WithHmacSHA256
     * @param password The plain text password
     * @param salt The salt to use
     * @return byte array containing the hashed password
     * @throws NoSuchAlgorithmException if the algorithm is not available
     * @throws InvalidKeySpecException if the key specification is invalid
     */
    private byte[] hashPassword(String password, byte[] salt) 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(), 
            salt, 
            ITERATIONS, 
            HASH_LENGTH * 8 // Convert bytes to bits
        );
        
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword(); // Clear the password from memory
        }
    }
    
    /**
     * Validate password strength
     * @param password The password to validate
     * @return true if password meets requirements, false otherwise
     */
    public boolean isValidPassword(String password) {
        return password != null && password.length() >= 6;
    }
    
    /**
     * Clear all users (for testing purposes)
     */
    public void clearAllUsers() {
        users.clear();
    }
}
