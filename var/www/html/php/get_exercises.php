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

    $currentWorkoutId = $_POST['workoutId'] ?? '';
    $workoutId = $conn->real_escape_string($currentWorkoutId);
    $user_id = $_SESSION['user_id'];
    
    $stmt = $conn->prepare("SELECT exercise_id, title, notes, category, duration_min, created_at, calories_burned FROM exercises 
                           WHERE user_id = ? AND workout_id = ?");
    $stmt->bind_param("ii", $user_id, $workoutId);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $exercises = $result->fetch_all(MYSQLI_ASSOC); 
    
    echo json_encode([
        'status' => 'success',
        'exercises' => $exercises 
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'status' => 'error',
        'message' => $e->getMessage()
    ]);
} finally {
    $conn->close();
    ob_end_flush();
    exit;
}
?>