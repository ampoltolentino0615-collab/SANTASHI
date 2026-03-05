<?php
require_once 'includes/auth.php';

// Set header for JSON response
header('Content-Type: application/json');

// Check if request is POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Invalid request method']);
    exit;
}

// Get form data
$fullName = $_POST['full_name'] ?? '';
$email = $_POST['email'] ?? '';
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$userType = $_POST['user_type'] ?? 'user';

// Create auth instance
$auth = new Auth();

// Attempt registration
$result = $auth->register($fullName, $email, $username, $password, $userType);

echo json_encode($result);
?>