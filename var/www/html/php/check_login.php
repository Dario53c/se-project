<?php

declare(strict_types=1);
ob_start();
header('Content-Type: application/json');

session_start();
if(isset($_SESSION['user_id'])) {
    echo json_encode([
        'username' => $_SESSION['username'],
        'logged_in' => true,
    ]);
} else {
    echo json_encode([
        'username' => null,
        'logged_in' => false,
    ]);
}

?>