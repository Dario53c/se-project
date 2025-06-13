<?php

declare(strict_types=1);
ob_start(); 
header('Content-Type: application/json');

session_start();
require_once 'database.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['status' => 'error', 'message' => 'User not authenticated']);
        exit;
    }
    $userId = $_SESSION['user_id'];

    // Sanitize and validate input
    $exerciseId = filter_input(INPUT_POST, 'exerciseId', FILTER_VALIDATE_INT);
    $exerciseName = htmlspecialchars($_POST['name'] ?? '');
    $exerciseNotes = htmlspecialchars($_POST['notes'] ?? '');
    $exerciseCategory = htmlspecialchars($_POST['category'] ?? '');
    $exerciseDuration = filter_input(INPUT_POST, 'duration', FILTER_VALIDATE_INT);

    if (!$exerciseId) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid exercise ID']);
        exit;
    }

     // Prepare the update query
    $stmt = $conn->prepare("UPDATE exercises SET category = ?, title = ?, duration_min = ?, notes = ?
     WHERE exercise_id = ? AND user_id = ?");
    
    $stmt->bind_param("ssisii", 
        $exerciseCategory, 
        $exerciseName, 
        $exerciseDuration, 
        $exerciseNotes, 
        $exerciseId,
        $userId
    );
    
    if ($stmt->execute()) {
        if ($stmt->affected_rows === 1) {
            echo json_encode(['status' => 'success', 'message' => 'Exercise updated successfully']);
        } else {
            // Either the exercise doesn't exist or doesn't belong to this user
            echo json_encode(['status' => 'error', 'message' => 'Exercise not found or not owned by user']);
        }
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Failed to update exercise']);
    }
    
    $stmt->close();
}