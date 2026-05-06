<?php
session_start();
header('Content-Type: application/json');

// Turn on error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Database configuration
$host = "localhost";
$username = "root";
$password = "";
$database = "login_system"; // Make sure this matches your database name

// Create connection
$conn = new mysqli($host, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    echo json_encode([
        'success' => false, 
        'message' => 'Database connection failed: ' . $conn->connect_error
    ]);
    exit;
}

// Get login data (works with both JSON and form data)
$input = json_decode(file_get_contents('php://input'), true);
if (!$input) {
    $input = $_POST;
}

$username = isset($input['username']) ? trim($input['username']) : '';
$password = isset($input['password']) ? $input['password'] : '';
$user_type = isset($input['user_type']) ? $input['user_type'] : 'user';
$remember = isset($input['remember']) ? true : false;
$dpa_accepted = isset($input['dpa_accepted']) ? true : false;

// Get IP address and user agent
$ip_address = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Validate input
if (empty($username) || empty($password)) {
    echo json_encode(['success' => false, 'message' => 'Username and password required']);
    exit;
}

// Query user
$sql = "SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ss", $username, $username);
$stmt->execute();
$result = $stmt->get_result();

// Log this login attempt
$user_id = null;
$success = false;

if ($result->num_rows === 0) {
    // Log failed attempt - user not found
    logLoginAttempt($conn, null, $username, $ip_address, $user_agent, false, 'user_not_found');
    echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
    exit;
}

$user = $result->fetch_assoc();
$user_id = $user['id'];

// Check if account is locked
if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
    logLoginAttempt($conn, $user_id, $username, $ip_address, $user_agent, false, 'account_locked');
    echo json_encode(['success' => false, 'message' => 'Account is locked. Please try again later.']);
    exit;
}

// Verify password
if (password_verify($password, $user['password_hash'])) {
    // Successful login
    $success = true;
    
    // Reset failed attempts
    $reset_sql = "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?";
    $reset_stmt = $conn->prepare($reset_sql);
    $reset_stmt->bind_param("i", $user_id);
    $reset_stmt->execute();
    
    // Update last login info
    $update_sql = "UPDATE users SET last_login = NOW(), last_login_ip = ? WHERE id = ?";
    $update_stmt = $conn->prepare($update_sql);
    $update_stmt->bind_param("si", $ip_address, $user_id);
    $update_stmt->execute();
    
    // Set session
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['user_type'] = $user['user_type'];
    $_SESSION['full_name'] = $user['full_name'];
    $_SESSION['login_time'] = time();
    
    // Create user session record
    createUserSession($conn, $user_id, $ip_address, $user_agent, $remember);
    
    // Log user activity
    logUserActivity($conn, $user_id, 'login', 'Logged in successfully', $ip_address, $user_agent);
    
    // Record DPA agreement if accepted
    if ($dpa_accepted) {
        recordDPAAgreement($conn, $user_id, $ip_address);
    }
    
    // Handle remember me
    if ($remember) {
        createRememberToken($conn, $user_id, $ip_address, $user_agent);
    }
    
    // Check user type
    if ($user_type === 'admin' && $user['user_type'] !== 'admin') {
        echo json_encode(['success' => false, 'message' => 'Not an admin account']);
        exit;
    }
    
    // Determine redirect
    $redirect = ($user['user_type'] === 'admin') ? 'admin-dashboard.html' : 'index.html';
    
    echo json_encode([
        'success' => true,
        'message' => 'Login successful',
        'user_type' => $user['user_type'],
        'username' => $user['username'],
        'full_name' => $user['full_name'],
        'redirect' => $redirect
    ]);
    
} else {
    // Failed password
    $failed_attempts = $user['failed_login_attempts'] + 1;
    
    // Check if too many failed attempts
    $lock_until = null;
    if ($failed_attempts >= 5) {
        $lock_until = date('Y-m-d H:i:s', strtotime('+30 minutes'));
    }
    
    // Update failed attempts
    $failed_sql = "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?";
    $failed_stmt = $conn->prepare($failed_sql);
    $failed_stmt->bind_param("isi", $failed_attempts, $lock_until, $user_id);
    $failed_stmt->execute();
    
    // Log failed attempt
    logLoginAttempt($conn, $user_id, $username, $ip_address, $user_agent, false, 'wrong_password');
    
    echo json_encode(['success' => false, 'message' => 'Invalid username or password']);
}

$stmt->close();
$conn->close();

// ======================================================
// Helper Functions
// ======================================================

function logLoginAttempt($conn, $user_id, $username, $ip, $agent, $success, $reason = null) {
    $sql = "INSERT INTO login_attempts (user_id, username_attempted, ip_address, user_agent, success, failure_reason) 
            VALUES (?, ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("isssis", $user_id, $username, $ip, $agent, $success, $reason);
    $stmt->execute();
    $stmt->close();
}

function createUserSession($conn, $user_id, $ip, $agent, $remember) {
    // Generate unique session token
    $session_token = bin2hex(random_bytes(32));
    
    // Determine device type and browser
    $device_type = 'desktop';
    $browser = 'Unknown';
    $os = 'Unknown';
    
    if (preg_match('/mobile/i', $agent)) {
        $device_type = 'mobile';
    } elseif (preg_match('/tablet/i', $agent)) {
        $device_type = 'tablet';
    }
    
    if (preg_match('/Chrome/i', $agent)) {
        $browser = 'Chrome';
    } elseif (preg_match('/Firefox/i', $agent)) {
        $browser = 'Firefox';
    } elseif (preg_match('/Safari/i', $agent)) {
        $browser = 'Safari';
    }
    
    if (preg_match('/Windows/i', $agent)) {
        $os = 'Windows';
    } elseif (preg_match('/Mac/i', $agent)) {
        $os = 'macOS';
    } elseif (preg_match('/Linux/i', $agent)) {
        $os = 'Linux';
    } elseif (preg_match('/iPhone/i', $agent)) {
        $os = 'iOS';
    } elseif (preg_match('/Android/i', $agent)) {
        $os = 'Android';
    }
    
    // Set expiry (24 hours from now, or longer if remember me)
    $expiry = $remember ? date('Y-m-d H:i:s', strtotime('+30 days')) : date('Y-m-d H:i:s', strtotime('+24 hours'));
    
    $sql = "INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, device_type, browser, os, login_time, expiry_time, is_active, remember_me) 
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?, 1, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("isssssssi", $user_id, $session_token, $ip, $agent, $device_type, $browser, $os, $expiry, $remember);
    $stmt->execute();
    $stmt->close();
    
    // Store in session
    $_SESSION['session_token'] = $session_token;
}

function logUserActivity($conn, $user_id, $activity_type, $description, $ip, $agent) {
    $sql = "INSERT INTO user_activities (user_id, activity_type, description, ip_address, user_agent, created_at) 
            VALUES (?, ?, ?, ?, ?, NOW())";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("issss", $user_id, $activity_type, $description, $ip, $agent);
    $stmt->execute();
    $stmt->close();
}

function recordDPAAgreement($conn, $user_id, $ip) {
    // Check if already agreed today
    $check_sql = "SELECT id FROM dpa_agreements WHERE user_id = ? AND DATE(agreed_at) = CURDATE()";
    $check_stmt = $conn->prepare($check_sql);
    $check_stmt->bind_param("i", $user_id);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    
    if ($check_result->num_rows == 0) {
        $sql = "INSERT INTO dpa_agreements (user_id, ip_address, agreement_version, terms_accepted, privacy_policy_accepted) 
                VALUES (?, ?, '1.0', 1, 1)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("is", $user_id, $ip);
        $stmt->execute();
        $stmt->close();
    }
    $check_stmt->close();
}

function createRememberToken($conn, $user_id, $ip, $agent) {
    // Delete old tokens for this user
    $delete_sql = "DELETE FROM remember_tokens WHERE user_id = ?";
    $delete_stmt = $conn->prepare($delete_sql);
    $delete_stmt->bind_param("i", $user_id);
    $delete_stmt->execute();
    
    // Create new token
    $token = bin2hex(random_bytes(32));
    $series = bin2hex(random_bytes(32));
    $expires = date('Y-m-d H:i:s', strtotime('+30 days'));
    
    $sql = "INSERT INTO remember_tokens (user_id, token, series, ip_address, user_agent, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("isssss", $user_id, $token, $series, $ip, $agent, $expires);
    $stmt->execute();
    $stmt->close();
    
    // Set cookie
    setcookie('remember_token', $token, time() + (86400 * 30), "/");
    setcookie('remember_series', $series, time() + (86400 * 30), "/");
}
?>