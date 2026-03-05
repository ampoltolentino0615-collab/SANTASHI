<?php
session_start();
require_once 'functions.php';

class Auth {
    private $functions;
    
    public function __construct() {
        $this->functions = new AuthFunctions();
    }
    
    // Handle login
    public function login($username, $password, $remember = false) {
        // Sanitize inputs
        $username = $this->functions->sanitize($username);
        $password = trim($password);
        
        // Get IP and User Agent
        $ip = $_SERVER['REMOTE_ADDR'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        
        // Check if account is locked
        if ($this->functions->isAccountLocked($username, $ip)) {
            $this->functions->logLoginAttempt($username, $ip, false);
            return [
                'success' => false,
                'message' => 'Account temporarily locked due to too many failed attempts. Please try again in 15 minutes.'
            ];
        }
        
        // Get user from database
        $user = $this->functions->getUserByUsername($username);
        
        if (!$user) {
            $this->functions->logLoginAttempt($username, $ip, false);
            return [
                'success' => false,
                'message' => 'Invalid username or password'
            ];
        }
        
        // Check if account is active
        if (!$user['is_active']) {
            $this->functions->logLoginAttempt($username, $ip, false);
            return [
                'success' => false,
                'message' => 'Account is deactivated. Please contact administrator.'
            ];
        }
        
        // Verify password
        if (!$this->functions->verifyPassword($password, $user['password_hash'])) {
            $this->functions->logLoginAttempt($username, $ip, false);
            return [
                'success' => false,
                'message' => 'Invalid username or password'
            ];
        }
        
        // Log successful attempt
        $this->functions->logLoginAttempt($username, $ip, true);
        
        // Create session
        $sessionId = $this->functions->createSession($user['id'], $ip, $userAgent);
        
        // Set session variables
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['user_type'] = $user['user_type'];
        $_SESSION['full_name'] = $user['full_name'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['logged_in'] = true;
        
        // Set remember me cookie if requested
        if ($remember) {
            $token = $this->functions->generateToken();
            $expiry = time() + (30 * 24 * 60 * 60); // 30 days
            
            setcookie('remember_token', $token, $expiry, '/');
            
            // Store token in database (you would need to create a remember_tokens table)
        }
        
        return [
            'success' => true,
            'message' => 'Login successful!',
            'user_type' => $user['user_type'],
            'user_id' => $user['id']
        ];
    }
    
    // Handle registration
    public function register($fullName, $email, $username, $password, $userType = 'user') {
        // Sanitize inputs
        $fullName = $this->functions->sanitize($fullName);
        $email = $this->functions->sanitize($email);
        $username = $this->functions->sanitize($username);
        $password = trim($password);
        
        // Validate email
        if (!$this->functions->validateEmail($email)) {
            return [
                'success' => false,
                'message' => 'Invalid email address'
            ];
        }
        
        // Check if username exists
        if ($this->functions->usernameExists($username)) {
            return [
                'success' => false,
                'message' => 'Username already exists'
            ];
        }
        
        // Check if email exists
        if ($this->functions->emailExists($email)) {
            return [
                'success' => false,
                'message' => 'Email already registered'
            ];
        }
        
        // Validate password strength
        if (strlen($password) < 8) {
            return [
                'success' => false,
                'message' => 'Password must be at least 8 characters long'
            ];
        }
        
        // Hash password
        $passwordHash = $this->functions->hashPassword($password);
        
        // Insert user into database
        $db = new Database();
        $sql = "INSERT INTO users (full_name, email, username, password_hash, user_type) VALUES (?, ?, ?, ?, ?)";
        
        try {
            $stmt = $db->query($sql, [$fullName, $email, $username, $passwordHash, $userType]);
            $userId = $stmt->insert_id;
            
            // Log DPA agreement if exists in localStorage (you would need to pass this from frontend)
            
            return [
                'success' => true,
                'message' => 'Registration successful! You can now login.',
                'user_id' => $userId
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'message' => 'Registration failed: ' . $e->getMessage()
            ];
        }
    }
    
    // Check if user is logged in
    public function isLoggedIn() {
        return isset($_SESSION['logged_in']) && $_SESSION['logged_in'] === true;
    }
    
    // Get current user
    public function getCurrentUser() {
        if ($this->isLoggedIn() && isset($_SESSION['user_id'])) {
            return $this->functions->getUserById($_SESSION['user_id']);
        }
        return null;
    }
    
    // Logout
    public function logout() {
        // Destroy session
        $_SESSION = array();
        
        // Destroy session cookie
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        
        // Destroy session
        session_destroy();
        
        // Clear remember me cookie
        setcookie('remember_token', '', time() - 3600, '/');
        
        return [
            'success' => true,
            'message' => 'Logged out successfully'
        ];
    }
}
?>