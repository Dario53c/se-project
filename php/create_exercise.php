<?php
declare(strict_types=1);
ob_start();
header('Content-Type: application/json');

session_start();
require_once 'database.php';

try {
    if (!isset($_SESSION['user_id'])) {
        throw new Exception('User not logged in');
    }

    $workoutId = $_POST['workoutId'] ?? '';
    if (empty($workoutId)) {
        throw new Exception('Workout ID is required');
    }

    $checkStmt = $conn->prepare("SELECT workout_id FROM workouts WHERE workout_id = ? AND user_id = ?");
    $checkStmt->bind_param("ii", $workoutId, $_SESSION['user_id']);
    $checkStmt->execute();
    
    if ($checkStmt->get_result()->num_rows === 0) {
        throw new Exception('Invalid workout or access denied');
    }

    $name = $_POST['name'] ?? '';
    $notes = $_POST['notes'] ?? '';
    $category = $_POST['category'] ?? '';
    $duration = $_POST['duration'] ?? '';

    $stmt = $conn->prepare("INSERT INTO exercises 
                          (user_id, workout_id, title, notes, category, duration_min) 
                          VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("iisssi", 
        $_SESSION['user_id'],
        $workoutId,
        $name,
        $notes,
        $category,
        $duration
    );

    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Exercise created successfully']);
    } else {
        throw new Exception('Failed to create exercise: ' . $stmt->error);
    }
} catch (Exception $e) {
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
} finally {
    $conn->close();
    ob_end_flush();
    exit;
}
?>