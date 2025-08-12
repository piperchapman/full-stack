// script.js

const API_BASE = "https://full-stack-production-b33c.up.railway.app/api";


// UI Elements
const loginForm = document.getElementById("loginForm");
const signupForm = document.getElementById("signupForm");
const loginFormElement = document.getElementById("loginFormElement");
const signupFormElement = document.getElementById("signupFormElement");
const showSignup = document.getElementById("showSignup");
const showLogin = document.getElementById("showLogin");
const loginMessage = document.getElementById("loginMessage");
const signupMessage = document.getElementById("signupMessage");
const authContainer = document.getElementById("authContainer");
const profileContainer = document.getElementById("profileContainer");
const profileInfo = document.getElementById("profileInfo");
const logoutBtn = document.getElementById("logoutBtn");
const loadingEl = document.getElementById("loading");

// Show/hide loading spinner
function showLoading(show) {
    if (show) {
        loadingEl.classList.remove("hidden");
    } else {
        loadingEl.classList.add("hidden");
    }
}

// Switch to signup form
showSignup.addEventListener("click", (e) => {
    e.preventDefault();
    loginForm.classList.add("hidden");
    signupForm.classList.remove("hidden");
    loginMessage.textContent = "";
    signupMessage.textContent = "";
});

// Switch to login form
showLogin.addEventListener("click", (e) => {
    e.preventDefault();
    signupForm.classList.add("hidden");
    loginForm.classList.remove("hidden");
    loginMessage.textContent = "";
    signupMessage.textContent = "";
});

// Save token to localStorage
function saveToken(token) {
    localStorage.setItem("authToken", token);
}

// Get token from localStorage
function getToken() {
    return localStorage.getItem("authToken");
}

// Remove token from localStorage
function clearToken() {
    localStorage.removeItem("authToken");
}

// Handle signup
signupFormElement.addEventListener("submit", async (e) => {
    e.preventDefault();
    signupMessage.textContent = "";
    showLoading(true);

    const username = document.getElementById("signupUsername").value.trim();
    const email = document.getElementById("signupEmail").value.trim();
    const password = document.getElementById("signupPassword").value;

    try {
        const res = await fetch(`${API_BASE}/signup`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password })
        });

        const data = await res.json();
        showLoading(false);

        if (!res.ok) {
            signupMessage.textContent = data.error || data;
            signupMessage.style.color = "red";
            return;
        }

        saveToken(data.token);
        loadProfile();
    } catch (err) {
        showLoading(false);
        signupMessage.textContent = "Error: " + err.message;
        signupMessage.style.color = "red";
    }
});

// Handle login
loginFormElement.addEventListener("submit", async (e) => {
    e.preventDefault();
    loginMessage.textContent = "";
    showLoading(true);

    const email = document.getElementById("loginEmail").value.trim();
    const password = document.getElementById("loginPassword").value;

    try {
        const res = await fetch(`${API_BASE}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();
        showLoading(false);

        if (!res.ok) {
            loginMessage.textContent = data.error || data;
            loginMessage.style.color = "red";
            return;
        }

        saveToken(data.token);
        loadProfile();
    } catch (err) {
        showLoading(false);
        loginMessage.textContent = "Error: " + err.message;
        loginMessage.style.color = "red";
    }
});

// Load profile
async function loadProfile() {
    const token = getToken();
    if (!token) {
        authContainer.classList.remove("hidden");
        profileContainer.classList.add("hidden");
        return;
    }

    showLoading(true);
    try {
        const res = await fetch(`${API_BASE}/profile`, {
            method: "GET",
            headers: { "Authorization": `Bearer ${token}` }
        });

        showLoading(false);

        if (!res.ok) {
            clearToken();
            authContainer.classList.remove("hidden");
            profileContainer.classList.add("hidden");
            return;
        }

        const user = await res.json();
        profileInfo.innerHTML = `
            <p><strong>ID:</strong> ${user.id}</p>
            <p><strong>Username:</strong> ${user.username}</p>
            <p><strong>Email:</strong> ${user.email}</p>
            <p><strong>Created At:</strong> ${new Date(user.created_at).toLocaleString()}</p>
        `;

        authContainer.classList.add("hidden");
        profileContainer.classList.remove("hidden");
    } catch (err) {
        showLoading(false);
        console.error(err);
    }
}

// Logout
logoutBtn.addEventListener("click", () => {
    clearToken();
    authContainer.classList.remove("hidden");
    profileContainer.classList.add("hidden");
});

// On page load, check if already logged in
document.addEventListener("DOMContentLoaded", loadProfile);
