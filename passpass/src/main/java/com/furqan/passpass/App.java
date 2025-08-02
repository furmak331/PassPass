package com.furqan.passpass;

import java.util.Scanner;

/**
 * PassPass - A simple password manager CLI application
 */
public class App 
{
    private static Scanner scanner = new Scanner(System.in);
    private static UserService userService = new UserService();
    
    public static void main( String[] args )
    {
        System.out.println("Welcome to PassPass - Your Password Manager!");
        System.out.println("==========================================");
        
        boolean running = true;
        while (running) {
            showMenu();
            int choice = getUserChoice();
            
            switch (choice) {
                case 1:
                    registerUser();
                    break;
                case 2:
                    loginUser();
                    break;
                case 3:
                    System.out.println("Thank you for using PassPass. Goodbye!");
                    running = false;
                    break;
                default:
                    System.out.println("Invalid option. Please try again.");
            }
            
            if (running) {
                System.out.println("\nPress Enter to continue...");
                scanner.nextLine();
            }
        }
        
        scanner.close();
    }
    
    private static void showMenu() {
        System.out.println("\n=== PassPass Main Menu ===");
        System.out.println("1. Register");
        System.out.println("2. Login");
        System.out.println("3. Exit");
        System.out.print("Please choose an option (1-3): ");
    }
    
    private static int getUserChoice() {
        try {
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline
            return choice;
        } catch (Exception e) {
            scanner.nextLine(); // Clear invalid input
            return -1;
        }
    }
    
    private static void registerUser() {
        System.out.println("\n=== User Registration ===");
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        
        if (userService.userExists(username)) {
            System.out.println("Username already exists! Please choose a different username.");
            return;
        }
        
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        
        if (!userService.isValidPassword(password)) {
            System.out.println("Password must be at least 6 characters long!");
            return;
        }
        
        try {
            if (userService.registerUser(username, password)) {
                System.out.println("Registration successful! You can now login with your credentials.");
            } else {
                System.out.println("Registration failed. Please try again.");
            }
        } catch (RuntimeException e) {
            System.out.println("Registration failed due to a system error. Please try again.");
        }
    }
    
    private static void loginUser() {
        System.out.println("\n=== User Login ===");
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        
        if (userService.authenticateUser(username, password)) {
            System.out.println("Login successful! Welcome, " + username + "!");
            // Here you could add more functionality for logged-in users
            showUserMenu(username);
        } else {
            System.out.println("Invalid username or password. Please try again.");
        }
    }
    
    private static void showUserMenu(String username) {
        System.out.println("\n=== Welcome " + username + " ===");
        System.out.println("Password management features coming soon!");
        System.out.println("For now, you are successfully logged in.");
    }
}
