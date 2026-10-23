
document.addEventListener("DOMContentLoaded", () => {
    const card = document.getElementById("card");
    const showSignup = document.getElementById("showSignup");
    const showLogin = document.getElementById("showLogin");

    // FLIP TO REGISTER
    if (card && showSignup) {
        showSignup.addEventListener("click", (event) => {
            event.preventDefault();
            card.classList.add("signup-mode");
        });
    }

    // FLIP BACK TO LOGIN
    if (card && showLogin) {
        showLogin.addEventListener("click", (event) => {
            event.preventDefault();
            card.classList.remove("signup-mode");
        });
    }

    // SHOW / HIDE PASSWORD
    document.querySelectorAll("[data-toggle]").forEach((button) => {
        button.addEventListener("click", () => {
            const input = document.getElementById(
                button.dataset.toggle
            );

            if (!input) return;

            const show = input.type === "password";

            input.type = show ? "text" : "password";

            button.textContent = show ? "◎" : "◉";

            button.setAttribute(
                "aria-label",
                show ? "Hide password" : "Show password"
            );
        });
    });

    // FORGOT PASSWORD
    const forgotButton = document.getElementById("forgotButton");

    if (forgotButton) {
        forgotButton.addEventListener("click", (event) => {
            event.preventDefault();

            // Open the Flask Forgot Password page
            window.location.href = "/forgot-password";
        });
    }

    // LOGIN VALIDATION
    const loginForm = document.getElementById("loginForm");

    if (loginForm) {
        loginForm.addEventListener("submit", (event) => {
            const email = loginForm.querySelector(
                '[name="email"]'
            );

            const password = loginForm.querySelector(
                '[name="password"]'
            );

            if (
                !email ||
                !password ||
                !email.value.trim() ||
                !password.value
            ) {
                event.preventDefault();
                alert("Please enter your email and password.");
            }

            // Valid form submits to Flask.
        });
    }

    // REGISTER VALIDATION
    const signupForm = document.getElementById("signupForm");

    if (signupForm) {
        signupForm.addEventListener("submit", (event) => {
            const password = document.getElementById(
                "signupPassword"
            );

            const confirmPassword = document.getElementById(
                "confirmPassword"
            );

            if (
                password &&
                confirmPassword &&
                password.value !== confirmPassword.value
            ) {
                event.preventDefault();

                alert("Passwords do not match!");

                confirmPassword.focus();
            }

            // Valid form submits to Flask.
        });
    }
});
