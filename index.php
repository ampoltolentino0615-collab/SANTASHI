<?php
// login.php

// Database configuration
$host = 'localhost';
$dbname = 'name';
$username = 'username';
$password = 'password';

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: application/json');

try {
    // Create PDO connection
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Get form data
    $user_type = $_POST['user_type'] ?? '';
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']) ? true : false;
    
    // Validate input
    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'message' => 'Please fill in all fields']);
        exit;
    }
    
    // Determine which table to query based on user type
    $table = ($user_type === 'admin') ? 'admins' : 'users';
    
    // Prepare SQL statement to prevent SQL injection
    $stmt = $pdo->prepare("SELECT * FROM $table WHERE username = :username");
    $stmt->bindParam(':username', $username);
    $stmt->execute();
    
    // Check if user exists
    if ($stmt->rowCount() > 0) {
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Verify password (assuming passwords are hashed)
        if (password_verify($password, $user['password'])) {
            // Start session
            session_start();
            
            // Store user data in session
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['user_type'] = $user_type;
            
            // Set remember me cookie if requested
            if ($remember) {
                $cookie_value = base64_encode($user['id'] . ':' . hash('sha256', $user['password']));
                setcookie('remember_me', $cookie_value, time() + (30 * 24 * 60 * 60), '/'); // 30 days
            }
            
            echo json_encode([
                'success' => true, 
                'message' => 'Login successful!', 
                'user_type' => $user_type
            ]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
        }
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
    }
    
} catch (PDOException $e) {
    echo json_encode(['success' => false, 'message' => 'Database error: ' . $e->getMessage()]);
}
?>
