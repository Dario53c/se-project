<?php

declare(strict_types=1);
ob_start(); 
header('Content-Type: application/json');

session_start();
require_once 'database.php';



    $exerciseId = 51;
    if (empty($exerciseId)) {
        echo json_encode(['status' => 'error', 'message' => 'Exercise ID not found!']);
        exit;
    }

    $stmt = $conn->prepare("SELECT * FROM exercises WHERE exercise_id = ?");
    $stmt->bind_param("i", $exerciseId);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $exercise = $result->fetch_assoc();
        echo json_encode(['status' => 'success', 'message' => 'Exercise found', 'exercise' => $exercise]);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Exercise not found!']);
    }
