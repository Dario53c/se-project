
async function loadWorkouts() {
    const workoutsList = document.getElementById('workoutsList');
    
    try {
        // Show loading state
        workoutsList.innerHTML = '<div class="loading">Loading workouts...</div>';
        
        const response = await fetch('php/get_workouts.php', {
            credentials: 'include' // Important for session cookies
        });
        
        // Check for HTTP errors
        if (!response.ok) {
            const error = await response.json().catch(() => null);
            throw new Error(error?.message || `Server returned ${response.status}`);
        }
        
        const data = await response.json();
        
        // Check for application errors
        if (data.status === 'error') {
            throw new Error(data.message || 'Unknown server error');
        }
        
        // Validate response structure
        if (!Array.isArray(data.workouts)) {
            console.error('Invalid response format:', data);
            throw new Error('Invalid data received from server');
        }
        
        renderWorkouts(data.workouts);
        
    } catch (error) {
        console.error('Error loading workouts:', error);
        
        // Show user-friendly error message
        workoutsList.innerHTML = `
            <div class="error-message">
                <p>Failed to load workouts</p>
                <p>${error.message}</p>
                <button onclick="loadWorkouts()">Retry</button>
            </div>
        `;
        
        // Optional: Send error to monitoring service
        // logErrorToService(error);
    }
}

function setupWorkoutListPage() {
    loadWorkouts();
    const workoutModal = document.getElementById('workoutModal');
    const workoutForm = document.getElementById('workoutForm');
    const workoutCancel = document.getElementById('workoutCancel');
    const workoutTriggers = document.querySelectorAll('.workout-container');

    if (!workoutModal || !workoutForm) {
        console.error('Required workout elements not found!');
        return;
    }

    // Open modal on click
    workoutTriggers.forEach(trigger => {
        trigger.addEventListener('click', () => {
            workoutModal.style.display = 'flex';
        });
    });

    // Handle form submit
    workoutForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const name = document.getElementById('workoutName').value;
        const description = document.getElementById('workoutDescription').value;

        const formData = new FormData();
        formData.append('name', name);
        formData.append('description', description);

        try {
            const response = await fetch('php/create_workout.php', {
                method: 'POST',
                body: formData
            });

            const result = await response.text();
            alert(result);

            if (result.includes("Workout log successful")) {
                workoutModal.style.display = 'none';
                loadWorkouts();
            }
        } catch (err) {
            console.error(err);
            alert("Error creating workout.");
        }

        e.target.reset();
    });

    // Close modal
    workoutCancel.addEventListener('click', () => {
        workoutModal.style.display = 'none';
    });

    window.addEventListener('click', (e) => {
        if (e.target === workoutModal) {
            workoutModal.style.display = 'none';
        }
    });
}

function renderWorkouts(workouts) {
    const workoutsList = document.getElementById('workoutsList');
    
    if (!workoutsList) {
        console.error('Workouts container not found');
        return;
    }
    
    if (!workouts || workouts.length === 0) {
        workoutsList.innerHTML = `
            <div class="empty-state">
                <p>No workouts found</p>
                <button onclick="showCreateWorkoutForm()">Create First Workout</button>
            </div>
        `;
        return;
    }
    
    workoutsList.innerHTML = workouts.map(workout => `
        <div class="workout-item" data-id="${workout.workout_id}">
            <div class="workout-header">
                <h3>${workout.name || 'Untitled Workout'}</h3>
                <span class="workout-date">
                    ${workout.created_at ? new Date(workout.created_at).toLocaleDateString() : 'No date'}
                </span>
            </div>
            <div class="exercise-data">
                ${workout.category ? `<p><strong>Type:</strong> ${workout.category}</p>` : ''}
                ${workout.description ? `<p>${workout.description}</p>` : ''}
                ${workout.estimated_duration ? `<p><strong>Duration:</strong> ${workout.estimated_duration} minutes</p>` : ''}
            </div>
            <div class="workout-actions">
                <button class="btn view-workout">View Details</button>
                <button class="btn delete-workout">Delete</button>
            </div>
        </div>
    `).join('');
    
    // Event delegation for better performance
    workoutsList.addEventListener('click', (e) => {
        const workoutItem = e.target.closest('.workout-item');
        if (!workoutItem) return;
        
        const workoutId = workoutItem.dataset.id;
        
        if (e.target.classList.contains('view-workout')) {
            viewWorkoutDetails(workoutId);
        } else if (e.target.classList.contains('delete-workout')) {
            deleteWorkout(workoutId);
        }
    });
}

async function deleteWorkout(workoutId) {
    if (!confirm('Are you sure you want to delete this workout?')) return;
    
    try {
        const response = await fetch('php/delete_workout.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ workoutId })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || 'Network response was not ok');
        }
        const result = await response.json();
        if (result.success) {
            loadWorkouts(); 
        } else {
            throw new Error(result.error || 'Failed to delete workout');
        }
    } catch (err) {
        console.error('Delete error:', err);
        alert('Delete failed: ' + (err.message || err));
    }
}


let exerciseFormHandler = null;

// Create Workout Page
function setupCreateWorkoutPage() {
    const exerciseModal = document.getElementById('exerciseModal');
    const exerciseForm = document.getElementById('exerciseForm');
    const exerciseCancel = document.getElementById('exerciseCancel');
    const exerciseTriggers = document.querySelectorAll('.exercise-container');

    const exerciseEditForm = document.getElementById('exerciseEditForm');
    const exerciseEditCancel = document.getElementById('exerciseEditCancel');

        // Close edit modal
    exerciseEditCancel.addEventListener('click', () => {
        const exerciseEditModal = document.getElementById('exerciseEditModal');
        exerciseEditModal.style.display = 'none';
    });

    window.addEventListener('click', (e) => {
        const exerciseEditModal = document.getElementById('exerciseEditModal');
        if (e.target === exerciseEditModal) {
            exerciseEditModal.style.display = 'none';
        }
    });

    if (!exerciseModal || !exerciseForm) {
        console.error('Required exercise elements not found!');
        return;
    }

    exerciseTriggers.forEach(trigger => {
        trigger.addEventListener('click', () => {
            exerciseModal.style.display = 'flex';
        });
    });


    if (exerciseFormHandler) {
        exerciseForm.removeEventListener('submit', exerciseFormHandler);
    }

    exerciseFormHandler = async function(e) {
        e.preventDefault();

        const name = document.getElementById('exerciseName').value;
        const notes = document.getElementById('exerciseNotes').value;
        const category = document.getElementById('exerciseCategory').value;
        const duration = document.getElementById('exerciseDuration').value;
        const workoutId = window.currentWorkoutId;
        
        const formData = new FormData();
        formData.append('name', name);
        formData.append('notes', notes);
        formData.append('category', category);
        formData.append('duration', duration);
        formData.append('workoutId', workoutId);

        try {
            const response = await fetch('php/create_exercise.php', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            
            if (result.success) {
                alert(result.message);
                exerciseModal.style.display = 'none';
                
                await viewWorkoutDetails(workoutId);
            } else {
                alert(result.error || 'Error creating exercise');
            }
        } catch (err) {
            console.error(err);
            alert("Error creating exercise.");
        }

        e.target.reset();
    };

    // Handle form submit
    exerciseForm.addEventListener('submit', exerciseFormHandler);

    // Close modal
    exerciseCancel.addEventListener('click', () => {
        exerciseModal.style.display = 'none';
    });

    window.addEventListener('click', (e) => {
        if (e.target === exerciseModal) {
            exerciseModal.style.display = 'none';
        }
    });
}


async function viewWorkoutDetails(workoutId) {
    window.location.hash = `create_workout`;

    window.currentWorkoutId = workoutId;
    
    // Wait for the page content to load
    await new Promise(resolve => {
        const checkContent = () => {
            if (document.getElementById('exercisesList')) {
                resolve();
            } else {
                setTimeout(checkContent, 50);
            }
        };
        checkContent();
    });

    setupCreateWorkoutPage();
    
    const exercisesList = document.getElementById('exercisesList');
    exercisesList.innerHTML = '';
    
    try {
        const formData = new FormData();
        formData.append('workoutId', workoutId);

        const response = await fetch('php/get_exercises.php', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json(); 
        
        if (data.status !== 'success' || !data.exercises) {
            throw new Error(data.message || 'Failed to load exercises');
        }
        
        if(data.exercises.length === 0) {
            exercisesList.innerHTML = '<p class="no-workouts">No exercises logged for this workout.</p>';
            return;
        }

        data.exercises.forEach(exercise => {
            const exerciseElement = document.createElement('div');
            exerciseElement.className = 'workout-item';
            exerciseElement.innerHTML = `
                <div class="workout-header">
                    <h3>${exercise.title}</h3>
                    <span class="workout-date">${new Date(exercise.created_at).toLocaleDateString()}</span>
                </div>
                <div class="exercise-data">
                    ${exercise.category ? `<p>Category: ${exercise.category}</p>` : ''}
                    ${exercise.notes ? `<p>Notes: ${exercise.notes}</p>` : ''}
                    ${exercise.calories_burned ? `<p>Calories: ${exercise.calories_burned}</p>` : ''}
                    ${exercise.duration_min ? `<p>Duration: ${exercise.duration_min} min</p>` : ''}
                </div>
                <div class="workout-actions">
                    <button class="edit-exercise" data-id="${exercise.exercise_id}">Edit</button>
                    <button class="delete-exercise" data-id="${exercise.exercise_id}">Delete</button>
                </div>
            `;
            
            exercisesList.appendChild(exerciseElement);
        });
        
        
        document.querySelectorAll('.view-exercise').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const exerciseId = e.target.getAttribute('data-id');
                EditExerciseDetails(exerciseId);
            });
        });
        
        document.querySelectorAll('.delete-exercise').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const exerciseId = e.target.getAttribute('data-id');
                deleteExercise(exerciseId);
            });
        });
            document.querySelectorAll('.edit-exercise').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const exerciseId = e.target.getAttribute('data-id');
                    showEditExerciseModal(exerciseId);
                });
            });
    } catch (err) {
        console.error('Error loading exercises:', err);
        exercisesList.innerHTML = `<p class="error">${err.message}</p>`;
    }
}

async function deleteExercise(exerciseId) {
    if (!confirm('Are you sure you want to delete this exercise?')) return;
    
    try {
        const response = await fetch('php/delete_exercise.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ exerciseId })
        });
        
        if (!response.ok) throw new Error('Network response was not ok');
        
        const result = await response.json();
        
        if (result.success) {
            viewWorkoutDetails(window.currentWorkoutId);
        } else {
            throw new Error(result.error || 'Failed to delete exercise');
        }
    } catch (err) {
        console.error('Delete error:', err);
        alert('Delete failed: ' + err.message);
    }
}

// handle multiple event listeners
let exerciseEditSubmitHandler = null;

async function showEditExerciseModal(exerciseId) {
    const exerciseEditModal = document.getElementById('exerciseEditModal');
    if (!exerciseEditModal) {
        console.error('Edit exercise modal not found');
        return;
    }
    const formData = new FormData();
    formData.append('exerciseId', exerciseId);

    const result = await fetch('php/getExerciseByID.php', {
        method: 'POST',
        body: formData
    });

    const data = await result.json();
    console.log('Exercise data:', data);
    
    if (!data || !data.exercise) {
        console.error('Exercise data not found');
        alert('Failed to load exercise details');
        return;
    }
    const exercise = data.exercise;
    const exerciseEditName = document.getElementById('exerciseEditName');
    const exerciseEditNotes = document.getElementById('exerciseEditNotes');
    const exerciseEditCategory = document.getElementById('exerciseEditCategory');
    const exerciseEditDuration = document.getElementById('exerciseEditDuration');

    exerciseEditName.value = exercise.title || '';
    exerciseEditNotes.value = exercise.notes || '';
    exerciseEditCategory.value = exercise.category || '';
    exerciseEditDuration.value = exercise.duration_min || '';

    const exerciseEditForm = document.getElementById('exerciseEditForm');

    if (exerciseEditSubmitHandler) {
        exerciseEditForm.removeEventListener('submit', exerciseEditSubmitHandler);
    }

        
    exerciseEditSubmitHandler = async (e) => {
        e.preventDefault();

        const name = document.getElementById('exerciseEditName').value;
        const notes = document.getElementById('exerciseEditNotes').value;
        const category = document.getElementById('exerciseEditCategory').value;
        const duration = document.getElementById('exerciseEditDuration').value;

        const formData = new FormData();
        formData.append('exerciseId', exerciseId);
        formData.append('name', name);
        formData.append('notes', notes);
        formData.append('category', category);
        formData.append('duration', duration);

        try {
            const response = await fetch('php/edit_exercise.php', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            if (result.status === 'success') {
                alert(result.message);
                exerciseEditModal.style.display = 'none';
                if (window.currentWorkoutId) {
                    await viewWorkoutDetails(window.currentWorkoutId);
                }
            } else {
                alert(result.error || 'Error updating exercise');
            }
        } catch (err) {
            console.error(err);
            alert("Error updating exercise.");
        }
    };
        
    // Add the new handler
    exerciseEditForm.addEventListener('submit', exerciseEditSubmitHandler);
    
    exerciseEditModal.style.display = 'flex';

}