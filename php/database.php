<?php
declare(strict_types=1);

// Load composer autoloader from root
require_once __DIR__ . '/../vendor/autoload.php';

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->load();

// DigitalOcean Managed Database credentials from .env
$host = $_ENV['DB_HOST'];
$username = $_ENV['DB_USER'];
$password = $_ENV['DB_PASS'];
$dbname = $_ENV['DB_NAME'];
$port = $_ENV['DB_PORT'];
$ssl_cert = $_ENV['DB_SSL_CERT'];
// Create connection with SSL
$conn = new mysqli();
$conn->ssl_set(NULL, NULL, $ssl_cert, NULL, NULL);
$conn->real_connect($host, $username, $password, $dbname, $port, NULL, MYSQLI_CLIENT_SSL);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

?>