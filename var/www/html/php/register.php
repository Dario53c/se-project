<?php
require_once 'database.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $newUsername = mysqli_real_escape_string($conn, $_POST['username']);
    $newEmail = mysqli_real_escape_string($conn, $_POST['email']);
    $newFirstName = mysqli_real_escape_string($conn, $_POST['firstname']);
    $newLastName = mysqli_real_escape_string($conn, $_POST['lastname']);
    $newPassword = mysqli_real_escape_string($conn, $_POST['password']);
    $gender = mysqli_real_escape_string($conn, $_POST['gender']);
    
    $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

    $checkQuery = "SELECT * FROM users WHERE username='$newUsername' OR email='$newEmail'";
    $result = $conn->query($checkQuery);

    if ($result->num_rows > 0) {

        echo "Username or email already taken!";
        exit;
    }

    $sql = "INSERT INTO users (username, email, password_hash, gender, first_name, last_name) VALUES ('$newUsername', '$newEmail', '$hashedPassword', '$gender', '$newFirstName', '$newLastName')";


    if ($conn->query($sql) === TRUE) {
        echo "Registration successful";  
    } else {
        echo "Error: " . $sql . "<br>" . $conn->error;  
    }
}

$conn->close();
?>
