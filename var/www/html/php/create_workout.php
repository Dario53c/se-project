<?php
session_start();
require_once 'database.php';

$workoutName = $_POST['name'] ?? '';
$workoutDescription = $_POST['description'] ?? '';

$name = $conn->real_escape_string($workoutName);
$description = $conn->real_escape_string($workoutDescription);

$user_id = $_SESSION['user_id'];

$sql = "INSERT INTO workouts (user_id, name, description) VALUES ('$user_id', '$name', '$description')";

if ($conn->query($sql) === TRUE) {
    
    //Get the ID of the newly inserted workout
    $newWorkoutId = $conn->insert_id;
    $_SESSION['current_workout_id'] = $newWorkoutId;

    echo "Workout log successful";  
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;  
}

$conn->close();
?>