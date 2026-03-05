<?php
require_once 'database.php';

class AuthFunctions {
    private $db;
    
    public function __construct() {
        $this->db = new Database();
    }
    
    // Hash password
    public function hashPassword($password) {
        return password_hash($password, PASSWORD_BCRYPT);
    }
    
    // Verify password
    public function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }
    
    // Generate random token
    public function generateToken($length = 32) {
        return bin2hex(random_bytes($length));
    }
    
    // Sanitize input
    public function sanitize($input) {
        $connection = $this->db->getConnection();
        return htmlspecialchars(strip_tags(trim($input)));
    }
    
    // Validate email
    public function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }
    
    // Check if username exists
    public function usernameExists($username) {
        $sql = "SELECT id FROM users WHERE username = ?";
        $stmt = $this->db->query($sql, [$username]);
        $result = $stmt->get_result();
        return $result->num_rows > 0;
    }
    
    // Check if email exists
    public function emailExists($email) {
        $sql = "SELECT id FROM users WHERE email = ?";
        $stmt = $this->db->query($sql, [$email]);
        $result = $stmt->get_result();
        return $result->num_rows > 0;
    }
    
    // Log login attempt
    public function logLoginAttempt($username, $ip, $successful) {
        $sql = "INSERT INTO login_attempts (username, ip_address, successful) VALUES (?, ?, ?)";
        $this->db->query($sql, [$username, $ip, $successful ? 1 : 0]);
    }
    
    // Check if account is locked (too many failed attempts)
    public function isAccountLocked($username, $ip, $maxAttempts = 5, $lockTime = 15) {
        $sql = "SELECT COUNT(*) as attempts 
                FROM login_attempts 
                WHERE (username = ? OR ip_address = ?) 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL ? MINUTE)
                AND successful = 0";
        
        $stmt = $this->db->query($sql, [$username, $ip, $lockTime]);
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        
        return $row['attempts'] >= $maxAttempts;
    }
    
    // Create session
    public function createSession($userId, $ip, $userAgent) {
        $sessionId = session_id();
        $sql = "INSERT INTO user_sessions (session_id, user_id, ip_address, user_agent) VALUES (?, ?, ?, ?)";
        $this->db->query($sql, [$sessionId, $userId, $ip, $userAgent]);
        
        // Update last login time
        $sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
        $this->db->query($sql, [$userId]);
        
        return $sessionId;
    }
    
    // Get user by username
    public function getUserByUsername($username) {
        $sql = "SELECT id, username, email, password_hash, user_type, full_name, is_active FROM users WHERE username = ?";
        $stmt = $this->db->query($sql, [$username]);
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            return $result->fetch_assoc();
        }
        
        return null;
    }
    
    // Get user by ID
    public function getUserById($userId) {
        $sql = "SELECT id, username, email, user_type, full_name, created_at FROM users WHERE id = ? AND is_active = 1";
        $stmt = $this->db->query($sql, [$userId]);
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            return $result->fetch_assoc();
        }
        
        return null;
    }
}
?>