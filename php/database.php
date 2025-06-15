<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

// Database credentials from environment
$host = $_ENV['DB_HOST'] ?? getenv('DB_HOST');
$username = $_ENV['DB_USER'] ?? getenv('DB_USER');
$password = $_ENV['DB_PASS'] ?? getenv('DB_PASS');
$dbname = $_ENV['DB_NAME'] ?? getenv('DB_NAME');
$port = (int)($_ENV['DB_PORT'] ?? getenv('DB_PORT'));
$ssl_cert = $_ENV['DB_SSL_CERT'] ?? getenv('DB_SSL_CERT');

// Initialize connection with error handling
$conn = new mysqli();
$conn->options(MYSQLI_OPT_CONNECT_TIMEOUT, 10); // 10 second timeout

try {
    // SSL configuration
    if (!$conn->ssl_set(NULL, NULL, $ssl_cert, NULL, NULL)) {
        throw new Exception("SSL configuration failed: " . $conn->error);
    }
    
    // Connection with timeout
    if (!$conn->real_connect($host, $username, $password, $dbname, $port, NULL, MYSQLI_CLIENT_SSL)) {
        throw new Exception("Connection failed: " . $conn->connect_error);
    }
    
    return $conn;
} catch (Exception $e) {
    error_log("Database connection error: " . $e->getMessage());
    die(json_encode([
        'status' => 'error',
        'message' => 'Database service unavailable. Please try again later.'
    ]));
}

?>