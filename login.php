<?php
session_start();
header('Content-Type: application/json');

// Debug: Log everything
error_log("=== LOGIN DEBUG START ===");

// Debug 1: Check if we're getting POST data
error_log("Request method: " . $_SERVER['REQUEST_METHOD']);
error_log("Content type: " . ($_SERVER['CONTENT_TYPE'] ?? 'Not set'));

// Debug 2: See raw input
$raw_input = file_get_contents('php://input');
error_log("Raw input: " . $raw_input);

// Try to decode JSON
$data = json_decode($raw_input, true);

if (!$data) {
    error_log("JSON decode failed!");
    
    // Try to get form data instead
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        error_log("Trying form data...");
        $data = $_POST;
        error_log("Form data: " . print_r($data, true));
    }
    
    if (!$data) {
        echo json_encode([
            'success' => false, 
            'message' => 'Invalid request - no data received',
            'debug' => [
                'method' => $_SERVER['REQUEST_METHOD'],
                'content_type' => $_SERVER['CONTENT_TYPE'] ?? 'Not set',
                'raw_input' => $raw_input,
                'post_data' => $_POST
            ]
        ]);
        exit;
    }
}

error_log("Data received: " . print_r($data, true));

// Database connection
$host = "localhost";
$dbname = "car_dealership_db";
$username = "root";
$password = "";

try {
    $conn = new mysqli($host, $username, $password, $dbname);
    
    if ($conn->connect_error) {
        error_log("Database connection failed: " . $conn->connect_error);
        echo json_encode(['success' => false, 'message' => 'Database connection failed']);
        exit;
    }
    
    error_log("Database connected successfully");
    
    // Get login credentials
    $username = isset($data['username']) ? trim($data['username']) : '';
    $password = isset($data['password']) ? $data['password'] : '';
    $user_type = isset($data['user_type']) ? $data['user_type'] : 'user';
    
    error_log("Login attempt - Username: $username, User Type: $user_type");
    
    if (empty($username) || empty($password)) {
        error_log("Empty username or password");
        echo json_encode(['success' => false, 'message' => 'Username and password are required']);
        exit;
    }
    
    // Query database
    $sql = "SELECT * FROM users WHERE username = ? AND user_type = ? AND is_active = TRUE";
    $stmt = $conn->prepare($sql);
    
    if (!$stmt) {
        error_log("Prepare failed: " . $conn->error);
        echo json_encode(['success' => false, 'message' => 'Database error']);
        exit;
    }
    
    $stmt->bind_param("ss", $username, $user_type);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        error_log("User not found: $username (type: $user_type)");
        echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
        exit;
    }
    
    $user = $result->fetch_assoc();
    error_log("User found: " . print_r($user, true));
    
    // Verify password
    if (password_verify($password, $user['password_hash'])) {
        error_log("Password verified successfully");
        
        // Update last login
        $update_sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
        $update_stmt = $conn->prepare($update_sql);
        $update_stmt->bind_param("i", $user['id']);
        $update_stmt->execute();
        
        // Store session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['user_type'] = $user['user_type'];
        $_SESSION['full_name'] = $user['full_name'];
        
        error_log("Session created for user: " . $user['username']);
        
        echo json_encode([
            'success' => true,
            'message' => 'Login successful',
            'user_type' => $user['user_type'],
            'username' => $user['username']
        ]);
        
    } else {
        error_log("Password verification failed");
        echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
    }
    
    $stmt->close();
    $conn->close();
    
} catch (Exception $e) {
    error_log("Exception: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Server error: ' . $e->getMessage()]);
}

error_log("=== LOGIN DEBUG END ===");
?>