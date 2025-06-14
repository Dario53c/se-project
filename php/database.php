<?php

// DigitalOcean Managed Database credentials
$host = 'db-mysql-fra1-72281-do-user-23308169-0.k.db.ondigitalocean.com'; // Your DO database host
$username = 'doadmin'; // Your DO database username
$password = 'AVNS_g3llEPlOarUHK-K3E3l'; // Your DO database password
$dbname = 'defaultdb'; // Usually 'defaultdb' unless you created another
$port = 25060; // Typical DO MySQL port
$ssl_cert = __DIR__ . '/ca-certificate.crt'; // Better path handling
// Create connection with SSL
$conn = new mysqli();
$conn->ssl_set(NULL, NULL, $ssl_cert, NULL, NULL);
$conn->real_connect($host, $username, $password, $dbname, $port, NULL, MYSQLI_CLIENT_SSL);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

?>