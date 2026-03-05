<?php
require_once 'includes/auth.php';

$auth = new Auth();
$result = $auth->logout();

// Redirect to login page
header('Location: login.html');
exit;
// In your login.php, add this check after successful login:
if ($user['user_type'] === 'admin' || $user['user_type'] === 'super_admin' || $user['user_type'] === 'moderator') {
    // Redirect to admin dashboard
    header('Location: admin-dashboard.php');
} else {
    // Redirect to user dashboard
    header('Location: index.php');
}
?>