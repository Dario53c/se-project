<?php
require '../vendor/autoload.php';
require_once 'config.php';
require_once 'database.php';
require_once 'Controller.php';

use Sssd\Controller;

Flight::route('POST /register', function() use ($conn) {
    header('Content-Type: application/json');

    $input = file_get_contents('php://input');
    if (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
        $data = json_decode($input, true);
    } else {
        $data = $_POST;
    }

    $controller = new Controller($conn);
    $controller->register($data);
});

Flight::route('POST /login', function() use ($conn) {
    session_start();
    header('Content-Type: application/json');

    $input = file_get_contents('php://input');
    if (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
        $data = json_decode($input, true);
    } else {
        $data = $_POST;
    }

    $controller = new Controller($conn);
    $controller->login($data);
});

Flight::route('POST /create-exercise', function() use ($conn) {
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
});

Flight::route('POST /create-workout', function() use ($conn) {
    header('Content-Type: application/json');

    // Handle both JSON and form-data submissions
    $input = file_get_contents('php://input');
    if (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
        $data = json_decode($input, true);
    } else {
        $data = $_POST;
    }

    $controller = new Sssd\Controller($conn);
    $controller->createWorkout($data);
});

Flight::route('GET /workouts', function() use ($conn) {
    header('Content-Type: application/json');
    session_start();

    try {
        // Check for active session
        if (!isset($_SESSION['user_id'])) {
            throw new Exception('Authentication required', 401);
        }

        $user_id = (int)$_SESSION['user_id'];
        error_log("Fetching workouts for user_id: $user_id");

        // Verify DB connection
        if (!$conn || $conn->connect_error) {
            throw new Exception('Database connection failed', 500);
        }

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

        $stmt->bind_param("i", $user_id);
        if (!$stmt->execute()) {
            throw new Exception("Execute failed: " . $stmt->error, 500);
        }

        $result = $stmt->get_result();
        $workouts = $result->fetch_all(MYSQLI_ASSOC);

        error_log("Found " . count($workouts) . " workouts");

        echo json_encode([
            'status' => 'success',
            'workouts' => $workouts,
            'debug' => [
                'user_id' => $user_id,
                'workout_count' => count($workouts)
            ]
        ]);
    } catch (Exception $e) {
        error_log("Error in /workouts: " . $e->getMessage());
        http_response_code($e->getCode() ?: 500);
        echo json_encode([
            'status' => 'error',
            'message' => $e->getMessage(),
            'error_code' => $e->getCode()
        ]);
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($conn)) $conn->close();
    }
});

Flight::route('POST /exercises', function() use ($conn) {
    ob_start();
    header('Content-Type: application/json');
    session_start();

    try {
        if (!isset($_SESSION['user_id'])) {
            throw new Exception('User not logged in');
        }

        $user_id = (int)$_SESSION['user_id'];

        // Accept both JSON and form-data
        $input = file_get_contents('php://input');
        $data = (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false)
            ? json_decode($input, true)
            : $_POST;

        if (!isset($data['workoutId'])) {
            throw new Exception('Workout ID is required');
        }

        $workoutId = (int) $data['workoutId'];

        $stmt = $conn->prepare("SELECT exercise_id, title, notes, category, duration_min, created_at, calories_burned 
                                FROM exercises 
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
        http_response_code(400);
        echo json_encode([
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($conn)) $conn->close();
        ob_end_flush();
    }
});

Flight::route('POST /exercise', function() use ($conn) {
    ob_start();
    header('Content-Type: application/json');
    session_start();

    try {
        // Support both JSON and form-data
        $input = file_get_contents('php://input');
        $data = (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false)
            ? json_decode($input, true)
            : $_POST;

        $exerciseId = $data['exerciseId'] ?? '';
        if (empty($exerciseId)) {
            throw new Exception('ID not found!');
        }

        $stmt = $conn->prepare("SELECT * FROM exercises WHERE exercise_id = ?");
        $stmt->bind_param("i", $exerciseId);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 1) {
            $exercise = $result->fetch_assoc();
            echo json_encode([
                'status' => 'success',
                'message' => 'Exercise found',
                'exercise' => $exercise
            ]);
        } else {
            throw new Exception('Exercise not found!');
        }

    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($conn)) $conn->close();
        ob_end_flush();
    }
});

Flight::route('POST /exercise/edit', function() use ($conn) {
    ob_start();
    header('Content-Type: application/json');
    session_start();

    try {
        if (!isset($_SESSION['user_id'])) {
            throw new Exception('User not authenticated');
        }
        $userId = (int)$_SESSION['user_id'];

        // Handle both JSON and form-data
        $input = file_get_contents('php://input');
        $data = (strpos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false)
            ? json_decode($input, true)
            : $_POST;

        // Sanitize input
        $exerciseId = filter_var($data['exerciseId'] ?? null, FILTER_VALIDATE_INT);
        $exerciseName = htmlspecialchars($data['name'] ?? '');
        $exerciseNotes = htmlspecialchars($data['notes'] ?? '');
        $exerciseCategory = htmlspecialchars($data['category'] ?? '');
        $exerciseDuration = filter_var($data['duration'] ?? null, FILTER_VALIDATE_INT);

        if (!$exerciseId) {
            throw new Exception('Invalid exercise ID');
        }

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

        if (!$stmt->execute()) {
            throw new Exception('Failed to update exercise');
        }

        if ($stmt->affected_rows === 1) {
            echo json_encode(['status' => 'success', 'message' => 'Exercise updated successfully']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Exercise not found or not owned by user']);
        }

    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'status' => 'error',
            'message' => $e->getMessage()
        ]);
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($conn)) $conn->close();
        ob_end_flush();
    }
});

Flight::route('POST /workout/delete', function() use ($conn) {
        header('Content-Type: application/json');
    session_start();

    try {
        if (!isset($_SESSION['user_id'])) {
            throw new Exception('User not logged in');
        }

        // Handle JSON input
        $data = json_decode(file_get_contents('php://input'), true);
        $workoutId = $data['workoutId'] ?? null;

        if (!$workoutId || !is_numeric($workoutId)) {
            throw new Exception('Workout ID is required');
        }

        $userId = (int)$_SESSION['user_id'];
        $workoutId = (int)$workoutId;

        // Verify ownership of workout
        $checkStmt = $conn->prepare("SELECT workout_id FROM workouts WHERE workout_id = ? AND user_id = ?");
        $checkStmt->bind_param("ii", $workoutId, $userId);
        $checkStmt->execute();
        $result = $checkStmt->get_result();

        if ($result->num_rows === 0) {
            throw new Exception('Workout not found or access denied');
        }

        // Delete exercises
        $deleteExercisesStmt = $conn->prepare("DELETE FROM exercises WHERE workout_id = ?");
        $deleteExercisesStmt->bind_param("i", $workoutId);
        if (!$deleteExercisesStmt->execute()) {
            throw new Exception('Failed to delete exercises: ' . $deleteExercisesStmt->error);
        }

        // Delete workout
        $deleteWorkoutStmt = $conn->prepare("DELETE FROM workouts WHERE workout_id = ?");
        $deleteWorkoutStmt->bind_param("i", $workoutId);
        if (!$deleteWorkoutStmt->execute()) {
            throw new Exception('Failed to delete workout: ' . $deleteWorkoutStmt->error);
        }

        echo json_encode([
            'success' => true,
            'message' => 'Workout and all associated exercises deleted successfully'
        ]);

    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    } finally {
        if (isset($checkStmt)) $checkStmt->close();
        if (isset($deleteExercisesStmt)) $deleteExercisesStmt->close();
        if (isset($deleteWorkoutStmt)) $deleteWorkoutStmt->close();
        $conn->close();
        exit;
    }
});

Flight::route('POST /exercise/delete', function() use ($conn) {
    header('Content-Type: application/json');
    session_start();

    try {
        if (!isset($_SESSION['user_id'])) {
            throw new Exception('User not logged in');
        }

        // Parse and validate input
        $data = json_decode(file_get_contents('php://input'), true);
        $exerciseId = $data['exerciseId'] ?? null;

        if (!$exerciseId || !is_numeric($exerciseId)) {
            throw new Exception('Exercise ID is required and must be numeric');
        }

        $exerciseId = (int) $exerciseId;
        $userId = (int) $_SESSION['user_id'];

        // Check if the exercise belongs to the user
        $checkStmt = $conn->prepare("SELECT exercise_id FROM exercises WHERE exercise_id = ? AND user_id = ?");
        $checkStmt->bind_param("ii", $exerciseId, $userId);
        $checkStmt->execute();

        if ($checkStmt->get_result()->num_rows === 0) {
            throw new Exception('Exercise not found or access denied');
        }

        // Delete the exercise
        $deleteStmt = $conn->prepare("DELETE FROM exercises WHERE exercise_id = ?");
        $deleteStmt->bind_param("i", $exerciseId);

        if (!$deleteStmt->execute()) {
            throw new Exception('Failed to delete exercise: ' . $deleteStmt->error);
        }

        echo json_encode([
            'success' => true,
            'message' => 'Exercise deleted successfully'
        ]);

    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    } finally {
        if (isset($checkStmt)) $checkStmt->close();
        if (isset($deleteStmt)) $deleteStmt->close();
        $conn->close();
        exit;
    }
});

Flight::route('GET /auth/check', function() {
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
});

Flight::route('GET /auth/logout', function() {
    session_start();
    session_destroy();
    echo 'Successfully logged out!';
});



Flight::route('GET /hello', function() {
    header('Content-Type: application/json');
    echo json_encode(['message' => 'Hello, world!']);
});

// Start Flight
Flight::start();
