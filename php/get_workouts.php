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

    $user_id = $_SESSION['user_id'];
    $stmt = $conn->prepare("SELECT workout_id, name, description, estimated_duration, category, created_at FROM workouts WHERE user_id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    
    $result = $stmt->get_result();
    $workouts = $result->fetch_all(MYSQLI_ASSOC);
    
    echo json_encode([
        'status' => 'success',
        'workouts' => $workouts
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