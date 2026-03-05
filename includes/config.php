<?php
// Database Configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', ''); // Default XAMPP password is empty
define('DB_NAME', 'car_dealership_db');

// Site Configuration
define('SITE_NAME', 'SANTASHI Car Dealership');
define('SITE_URL', 'http://localhost/car-dealership/');

// Security Configuration
define('SALT', 'your_secret_salt_here_change_this');
define('JWT_SECRET', 'your_jwt_secret_key_change_this');

// Timezone
date_default_timezone_set('Asia/Manila');
?>