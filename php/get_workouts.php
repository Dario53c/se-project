<?php
declare(strict_types=1);
header('Content-Type: application/json');
session_start();

require_once 'database.php';

try {
    // Verify session and user
    if (!isset($_SESSION['user_id'])) {
        throw new Exception('Authentication required', 401);
    }

    $user_id = (int)$_SESSION['user_id'];

    // Debugging: Log the request
    error_log("Fetching workouts for user_id: $user_id");

    // Verify database connection
    if (!$conn || $conn->connect_error) {
        throw new Exception('Database connection failed', 500);
    }

    // Prepare statement with error handling
    $stmt = $conn->prepare("SELECT 
            workout_id, 
            name, 
            description, 
            estimated_duration, 
            category, 
            created_at 
        FROM workouts 
        WHERE user_id = ?");

    if (!$stmt) {
        throw new Exception("Prepare failed: " . $conn->error, 500);
    }

    // Bind and execute
    $stmt->bind_param("i", $user_id);
    if (!$stmt->execute()) {
        throw new Exception("Execute failed: " . $stmt->error, 500);
    }

    // Get results
    $result = $stmt->get_result();
    $workouts = $result->fetch_all(MYSQLI_ASSOC);

    // Debug output
    error_log("Found " . count($workouts) . " workouts");

    // Return success
    echo json_encode([
        'status' => 'success',
        'workouts' => $workouts,
        'debug' => [ // Only include in development
            'user_id' => $user_id,
            'workout_count' => count($workouts)
        ]
    ]);

} catch (Exception $e) {
    error_log("Error in get_workouts: " . $e->getMessage());
    http_response_code($e->getCode() ?: 500);
    echo json_encode([
        'status' => 'error',
        'message' => $e->getMessage(),
        'error_code' => $e->getCode()
    ]);
} finally {
    if (isset($stmt)) $stmt->close();
    if (isset($conn)) $conn->close();
    exit;
}