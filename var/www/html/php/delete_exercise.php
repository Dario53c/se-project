<?php
declare(strict_types=1);
header('Content-Type: application/json');
session_start();
require_once 'database.php';

try {
    if (!isset($_SESSION['user_id'])) {
        throw new Exception('User not logged in');
    }

    // Get and validate input
    $data = json_decode(file_get_contents('php://input'), true);
    $exerciseId = $data['exerciseId'] ?? '';
    
    if (empty($exerciseId)) {
        throw new Exception('Exercise ID is required');
    }

    // First verify the exercise belongs to the logged-in user
    $checkStmt = $conn->prepare("SELECT exercise_id FROM exercises 
                                WHERE exercise_id = ? AND user_id = ?");
    $checkStmt->bind_param("ii", $exerciseId, $_SESSION['user_id']);
    $checkStmt->execute();
    
    if ($checkStmt->get_result()->num_rows === 0) {
        throw new Exception('Exercise not found or access denied');
    }

    // Delete the exercise
    $deleteStmt = $conn->prepare("DELETE FROM exercises WHERE exercise_id = ?");
    $deleteStmt->bind_param("i", $exerciseId);

    if ($deleteStmt->execute()) {
        echo json_encode([
            'success' => true,
            'message' => 'Exercise deleted successfully'
        ]);
    } else {
        throw new Exception('Failed to delete exercise: ' . $deleteStmt->error);
    }
} catch (Exception $e) {
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
} finally {
    $conn->close();
    exit;
}
?>