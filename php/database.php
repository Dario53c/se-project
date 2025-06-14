<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

// DigitalOcean Managed Database credentials
$host = $_ENV['DB_HOST'] ?? getenv('DB_HOST');
$username = $_ENV['DB_USER'] ?? getenv('DB_USER');
$password = $_ENV['DB_PASS'] ?? getenv('DB_PASS');
$dbname = $_ENV['DB_NAME'] ?? getenv('DB_NAME');
$port = (int)($_ENV['DB_PORT'] ?? getenv('DB_PORT'));
$ssl_cert = $_ENV['DB_SSL_CERT'] ?? getenv('DB_SSL_CERT');

// Create connection with SSL
$conn = new mysqli();
$conn->ssl_set(NULL, NULL, $ssl_cert, NULL, NULL);
$conn->real_connect($host, $username, $password, $dbname, $port, NULL, MYSQLI_CLIENT_SSL);

if ($conn->connect_error) {
    error_log("DB Connection failed: " . $conn->connect_error);
    die("Database maintenance in progress. Please try again later.");
}
?>