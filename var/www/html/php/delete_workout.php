<?php
declare(strict_types=1);
header('Content-Type: application/json');
session_start();
require_once 'database.php';

try {
    if (!isset($_SESSION['user_id'])) {
        throw new Exception('User not logged in');
    }

    $data = json_decode(file_get_contents('php://input'), true);
    $workoutId = $data['workoutId'] ?? '';
    
    if (empty($workoutId)) {
        throw new Exception('Workout ID is required');
    }

    // First verify the workout belongs to the logged-in user
    $checkStmt = $conn->prepare("SELECT workout_id FROM workouts 
                                WHERE workout_id = ? AND user_id = ?");
    $checkStmt->bind_param("ii", $workoutId, $_SESSION['user_id']);
    $checkStmt->execute();
    
    if ($checkStmt->get_result()->num_rows === 0) {
        throw new Exception('Workout not found or access denied');
    }

    // Delete all exercises for this workout first
    $deleteExercisesStmt = $conn->prepare("DELETE FROM exercises WHERE workout_id = ?");
    $deleteExercisesStmt->bind_param("i", $workoutId);
    
    if (!$deleteExercisesStmt->execute()) {
        throw new Exception('Failed to delete exercises: ' . $deleteExercisesStmt->error);
    }

    // Then delete the workout
    $deleteWorkoutStmt = $conn->prepare("DELETE FROM workouts WHERE workout_id = ?");
    $deleteWorkoutStmt->bind_param("i", $workoutId);

    if ($deleteWorkoutStmt->execute()) {
        echo json_encode([
            'success' => true,
            'message' => 'Workout and all associated exercises deleted successfully'
        ]);
    } else {
        throw new Exception('Failed to delete workout: ' . $deleteWorkoutStmt->error);
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