<?php
declare(strict_types=1);

// CORS Headers (must be at the very top, before any output)
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With");
header("Access-Control-Allow-Credentials: true");
header("Content-Type: application/json");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/config.php';

// Database credentials from environment
$host = DB_HOST;
$username = DB_USER;
$password = DB_PASS;
$dbname = DB_NAME;
$port = DB_PORT;
$ssl_cert = DB_SSL_CERT;

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