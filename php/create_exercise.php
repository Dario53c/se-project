<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/Controller.php';

header('Content-Type: application/json');

// Handle both JSON and form-data submissions
$input = file_get_contents('php://input');
if (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
    $data = json_decode($input, true);
} else {
    $data = $_POST;
}

$controller = new Sssd\Controller($conn);
$controller->createExercise($data);