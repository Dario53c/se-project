function handleNavigation() {
    const hash = window.location.hash.substring(1) || 'home';
    updateRegisterButtons();
    loadContent(hash);

}
window.addEventListener('hashchange', handleNavigation);
handleNavigation();
// Load content partials
async function loadContent(page) {
    const contentContainer = document.getElementById('main-content');
    let url = `html/${page}.html`;

    try {
        const response = await fetch(url);
        if (!response.ok) throw new Error('Page not found');
        contentContainer.innerHTML = await response.text();
        formHandler(page);
    } catch (error) {
        contentContainer.innerHTML = '<h2>Page not found</h2>';
    }
}

// Initialize page-specific scripts
function formHandler(page) {
    const navbar = document.getElementById('navbar');
    if (page === 'login') {
        document.getElementById('loginForm').addEventListener('submit', handleLogin);
        navbar.style.display = "none";
    }
    else if (page === 'register') {
        document.getElementById('registerForm').addEventListener('submit', handleRegister);
        navbar.style.display = "none";
    } else if (page == 'workout_list') {
        navbar.style.display = "flex";
        setupWorkoutListPage();
    } else {
        navbar.style.display = "flex";
    }
}

// Login handler
async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    const formData = new FormData();
    formData.append('username', username);
    formData.append('password', password); 
    
    fetch('php/login.php', {
        method: 'POST',
        body: formData
    }).then(response => response.text())    
    .then(data => {
        if (data.includes("Login successful")) {
            alert(data);
            updateRegisterButtons();
            window.location.hash = "home";
        } else {
            alert(data);
        }
    })
}

// Register handler
async function handleRegister(e) {
    e.preventDefault();
    const email = document.getElementById('register-email').value;
    const username = document.getElementById('register-username').value;
    const firstname = document.getElementById('register-firstname').value;
    const lastname = document.getElementById('register-lastname').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm-password').value;
    const gender = document.querySelector('input[name="gender"]:checked').value;
    const passwordText = document.getElementById('password-text');

    if (confirmPassword !== password) {
        passwordText.style.display = "inline";
        return;
    }

    const formData = new FormData();
    formData.append('email', email);
    formData.append('username', username);
    formData.append('firstname', firstname);
    formData.append('lastname', lastname);
    formData.append('password', password);
    formData.append('gender', gender);

    fetch('php/register.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(data => {
        alert(data);
        if (data.includes("Registration successful")) {
            window.location.hash = "login";
        }
    })
    .catch(error => console.error('Error:', error));
}



// Displays either Login and Register or Welcome and Logout buttons
function updateRegisterButtons(){
    fetch('php/check_login.php')
    .then(response => response.json()).then(data => {
        const otherLinks = document.getElementById('other-links');
        const displayLinks = document.getElementById('nav-links-registration');
        if(data.logged_in) {
            otherLinks.innerHTML = `
                <span><span class="welcome_text">Welcome, </span>${data.username}</span>
                <a href="#home" class="nav-link">Home</a>
                <a href="#workout_list" class="nav-link">Workouts</a>
                <a href="#goals" class="nav-link">Goals</a>
            `;

            displayLinks.innerHTML = `
                <a href="#" class="nav-link" id="logout-button">Logout</a>
            `;
            const logoutBtn = document.getElementById('logout-button');
            logoutBtn.addEventListener('click', function() {
                if (!confirm('Are you sure you want to logout?')) return;
                fetch('php/logout.php')
                .then(response => response.text())
                .then(data => {
                    alert(data);
                    window.location.hash = "home";
                });
            });
        } else {
            otherLinks.innerHTML = `
                <a href="#home" class="nav-link">Home</a>
            `;
            displayLinks.innerHTML = `
                <a href="#login" class="nav-link">Login</a>
                <a href="#register" class="nav-link">Register</a>
            `;
        }
    });
}