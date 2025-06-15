<?php
namespace Sssd;

use OpenApi\Annotations as OA;

class Controller {
    private $conn;

    public function __construct($dbConnection) {
        $this->conn = $dbConnection;
    }

    /**
     * @OA\Post(
     *     path="/register.php",
     *     summary="Register a new user",
     *     description="Creates a new user account",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="User registration data",
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"username", "email", "password", "firstname", "lastname", "gender"},
     *                 @OA\Property(property="username", type="string", example="john_doe"),
     *                 @OA\Property(property="email", type="string", format="email", example="john@example.com"),
     *                 @OA\Property(property="password", type="string", format="password", minLength=8, example="SecurePass123!"),
     *                 @OA\Property(property="firstname", type="string", example="John"),
     *                 @OA\Property(property="lastname", type="string", example="Doe"),
     *                 @OA\Property(property="gender", type="string", enum={"male", "female", "other"}, example="male")
     *             )
     *         ),
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"username", "email", "password", "firstname", "lastname", "gender"},
     *                 @OA\Property(property="username", type="string", example="john_doe"),
     *                 @OA\Property(property="email", type="string", format="email", example="john@example.com"),
     *                 @OA\Property(property="password", type="string", format="password", minLength=8, example="SecurePass123!"),
     *                 @OA\Property(property="firstname", type="string", example="John"),
     *                 @OA\Property(property="lastname", type="string", example="Doe"),
     *                 @OA\Property(property="gender", type="string", enum={"male", "female", "other"}, example="male")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User registered successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Registration successful")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Missing required fields")
     *         )
     *     ),
     *     @OA\Response(
     *         response=409,
     *         description="Conflict",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Username or email already exists")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Registration failed")
     *         )
     *     )
     * )
     */
    public function register($data = null) {
        try {
            $data = $data ?? $_POST;
            $required = ['username', 'email', 'password', 'firstname', 'lastname', 'gender'];
            
            // Validate required fields
            foreach ($required as $field) {
                if (empty($data[$field])) {
                    http_response_code(400);
                    echo json_encode([
                        'status' => 'error',
                        'message' => "Missing required field: $field"
                    ]);
                    return;
                }
            }

            // Sanitize inputs
            $username = $this->sanitizeInput($data['username']);
            $email = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
            $firstname = $this->sanitizeInput($data['firstname']);
            $lastname = $this->sanitizeInput($data['lastname']);
            $password = $data['password'];
            $gender = in_array(strtolower($data['gender']), ['male', 'female', 'other']) 
                ? strtolower($data['gender']) 
                : null;

            // Additional validation
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new \Exception("Invalid email format");
            }

            if (!$gender) {
                throw new \Exception("Gender must be male, female, or other");
            }

            if (strlen($password) < 8) {
                throw new \Exception("Password must be at least 8 characters");
            }

            // Check if user exists
            $stmt = $this->conn->prepare("SELECT user_id FROM users WHERE username = ? OR email = ?");
            $stmt->bind_param("ss", $username, $email);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                http_response_code(409);
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Username or email already exists'
                ]);
                $stmt->close();
                return;
            }
            $stmt->close();

            // Hash password
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Insert new user
            $stmt = $this->conn->prepare("INSERT INTO users (username, email, password_hash, gender, first_name, last_name) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssss", $username, $email, $hashedPassword, $gender, $firstname, $lastname);

            if ($stmt->execute()) {
                http_response_code(201);
                echo json_encode([
                    'status' => 'success',
                    'message' => 'Registration successful'
                ]);
            } else {
                throw new \Exception("Database error: " . $stmt->error);
            }
        } catch (\Exception $e) {
            http_response_code(500);
            echo json_encode([
                'status' => 'error',
                'message' => $e->getMessage()
            ]);
        }
    }

        /**
     * @OA\Post(
     *     path="/login.php",
     *     summary="User login",
     *     description="Authenticates a user and creates a session",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         description="Login credentials",
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"username", "password"},
     *                 @OA\Property(property="username", type="string", example="john_doe"),
     *                 @OA\Property(property="password", type="string", format="password", example="SecurePass123!")
     *             )
     *         ),
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"username", "password"},
     *                 @OA\Property(property="username", type="string", example="john_doe"),
     *                 @OA\Property(property="password", type="string", format="password", example="SecurePass123!")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login successful",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Login successful")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Invalid credentials")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Bad request",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Missing required fields")
     *         )
     *     )
     * )
     */
    public function login($data = null) {
        try {
            $data = $data ?? $_POST;
            
            // Validate required fields
            if (empty($data['username']) || empty($data['password'])) {
                http_response_code(400);
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Username and password are required'
                ]);
                return;
            }

            $username = $this->sanitizeInput($data['username']);
            $password = $data['password'];

            // Get user from database
            $stmt = $this->conn->prepare("SELECT user_id, username, password_hash FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 1) {
                $user = $result->fetch_assoc();
                
                if (password_verify($password, $user['password_hash'])) {
                    $_SESSION['user_id'] = $user['user_id'];
                    $_SESSION['username'] = $user['username'];
                    
                    echo json_encode([
                        'status' => 'success',
                        'message' => 'Login successful'
                    ]);
                } else {
                    http_response_code(401);
                    echo json_encode([
                        'status' => 'error',
                        'message' => 'Invalid credentials'
                    ]);
                }
            } else {
                http_response_code(401);
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Invalid credentials'
                ]);
            }
        } catch (\Exception $e) {
            http_response_code(500);
            echo json_encode([
                'status' => 'error',
                'message' => 'Login failed: ' . $e->getMessage()
            ]);
        }
    }

        /**
     * @OA\Post(
     *     path="/create_workout.php",
     *     summary="Create a new workout",
     *     description="Creates a new workout for the authenticated user",
     *     tags={"Workouts"},
     *     security={{"sessionAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         description="Workout details",
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"name"},
     *                 @OA\Property(property="name", type="string", example="Morning Routine"),
     *                 @OA\Property(property="description", type="string", example="Cardio and strength training")
     *             )
     *         ),
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"name"},
     *                 @OA\Property(property="name", type="string", example="Morning Routine"),
     *                 @OA\Property(property="description", type="string", example="Cardio and strength training")
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Workout created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Workout created"),
     *             @OA\Property(property="workout_id", type="integer", example=123)
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Missing required fields",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Workout name is required")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Not authenticated")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to create workout")
     *         )
     *     )
     * )
     */
    public function createWorkout($data = null) {
        try {
            session_start();
            $data = $data ?? $_POST;

            // Check authentication
            if (!isset($_SESSION['user_id'])) {
                http_response_code(401);
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Not authenticated'
                ]);
                return;
            }

            // Validate required fields
            if (empty($data['name'])) {
                http_response_code(400);
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Workout name is required'
                ]);
                return;
            }

            // Sanitize inputs
            $name = $this->sanitizeInput($data['name']);
            $description = isset($data['description']) ? $this->sanitizeInput($data['description']) : '';
            $user_id = $_SESSION['user_id'];

            // Use prepared statement
            $stmt = $this->conn->prepare("INSERT INTO workouts (user_id, name, description) VALUES (?, ?, ?)");
            $stmt->bind_param("iss", $user_id, $name, $description);

            if ($stmt->execute()) {
                $newWorkoutId = $this->conn->insert_id;
                $_SESSION['current_workout_id'] = $newWorkoutId;

                http_response_code(201);
                echo json_encode([
                    'status' => 'success',
                    'message' => 'Workout log successful',
                    'workout_id' => $newWorkoutId
                ]);
            } else {
                throw new \Exception("Database error: " . $stmt->error);
            }
        } catch (\Exception $e) {
            http_response_code(500);
            echo json_encode([
                'status' => 'error',
                'message' => 'Failed to create workout: ' . $e->getMessage()
            ]);
        }
    }

    /**
     * @OA\Post(
     *     path="/create_exercise.php",
     *     summary="Create a new exercise",
     *     description="Adds a new exercise to an existing workout",
     *     tags={"Exercises"},
     *     security={{"sessionAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         description="Exercise details",
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 required={"workoutId", "name", "category", "duration"},
     *                 @OA\Property(property="workoutId", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="Bench Press"),
     *                 @OA\Property(property="notes", type="string", example="3 sets of 10 reps"),
     *                 @OA\Property(
     *                     property="category", 
     *                     type="string", 
     *                     enum={"strength-training", "calisthetics", "flexibility", "functional-training", "cardio"},
     *                     example="strength-training"
     *                 ),
     *                 @OA\Property(property="duration", type="integer", example=10)
     *             )
     *         ),
     *         @OA\MediaType(
     *             mediaType="application/json",
     *             @OA\Schema(
     *                 required={"workoutId", "name", "category", "duration"},
     *                 @OA\Property(property="workoutId", type="integer", example=1),
     *                 @OA\Property(property="name", type="string", example="Bench Press"),
     *                 @OA\Property(property="notes", type="string", example="3 sets of 10 reps"),
     *                 @OA\Property(
     *                     property="category", 
     *                     type="string", 
     *                     enum={"strength-training", "calisthetics", "flexibility", "functional-training", "cardio"},
     *                     example="strength-training"
     *                 ),
     *                 @OA\Property(property="duration", type="integer", example=10)
     *             )
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="Exercise created successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="success"),
     *             @OA\Property(property="message", type="string", example="Exercise created successfully")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Missing required fields")
     *         )
     *     ),
     *     @OA\Response(
     *         response=401,
     *         description="Unauthorized",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="User not logged in")
     *         )
     *     ),
     *     @OA\Response(
     *         response=403,
     *         description="Forbidden",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Invalid workout or access denied")
     *         )
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Server error",
     *         @OA\JsonContent(
     *             @OA\Property(property="status", type="string", example="error"),
     *             @OA\Property(property="message", type="string", example="Failed to create exercise")
     *         )
     *     )
     * )
     */
    public function createExercise($data = null) {
        try {
            session_start();
            $data = $data ?? $_POST;

            // Check authentication
            if (!isset($_SESSION['user_id'])) {
                http_response_code(401);
                echo json_encode([
                    'status' => 'error',
                    'message' => 'User not logged in'
                ]);
                return;
            }

            // Validate required fields
            $required = ['workoutId', 'name', 'category', 'duration'];
            foreach ($required as $field) {
                if (empty($data[$field])) {
                    http_response_code(400);
                    echo json_encode([
                        'status' => 'error',
                        'message' => 'Missing required fields'
                    ]);
                    return;
                }
            }

            // Validate workout ownership
            $workoutId = (int)$data['workoutId'];
            $userId = $_SESSION['user_id'];

            $checkStmt = $this->conn->prepare("SELECT workout_id FROM workouts WHERE workout_id = ? AND user_id = ?");
            $checkStmt->bind_param("ii", $workoutId, $userId);
            $checkStmt->execute();
            
            if ($checkStmt->get_result()->num_rows === 0) {
                http_response_code(403);
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Invalid workout or access denied'
                ]);
                $checkStmt->close();
                return;
            }
            $checkStmt->close();

            // Sanitize inputs
            $name = $this->sanitizeInput($data['name']);
            $notes = isset($data['notes']) ? $this->sanitizeInput($data['notes']) : '';
            $category = $this->sanitizeInput($data['category']);
            $duration = (int)$data['duration'];

            // Validate category
            $allowedCategories = ['strength-training', 'calisthetics', 'flexibility', 'functional-training', 'cardio'];
            if (!in_array($category, $allowedCategories)) {
                http_response_code(400);
                echo json_encode([
                    'status' => 'error',
                    'message' => 'Invalid exercise category'
                ]);
                return;
            }

            // Create exercise
            $stmt = $this->conn->prepare("INSERT INTO exercises 
                (user_id, workout_id, title, notes, category, duration_min) 
                VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("iisssi", 
                $userId,
                $workoutId,
                $name,
                $notes,
                $category,
                $duration
            );

            if ($stmt->execute()) {
                http_response_code(201);
                echo json_encode([
                    'success' => true,
                    'message' => 'Exercise created successfully'
                ]);
            } else {
                throw new \Exception('Database error: ' . $stmt->error);
            }
        } catch (\Exception $e) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'message' => 'Failed to create exercise: ' . $e->getMessage()
            ]);
        }
    }

    private function sanitizeInput($data) {
        return htmlspecialchars(strip_tags(trim($data)));
    }
}