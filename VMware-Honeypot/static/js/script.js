document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
    const messageBox = document.getElementById('message');
    const messageText = document.getElementById('message-text');
    const animatedCharacter = document.getElementById('animated-character');

    loginForm.addEventListener('submit', function(event) {
        event.preventDefault(); // Prevent the form from submitting the traditional way

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        // Only show the message and character if both username and password have been entered
        if (username && password) {
            // Display the message and image
            messageText.style.display = 'block';
            messageText.textContent = '"You didn\'t say the magic word"'; // Set the text content
            animatedCharacter.style.display = 'block'; // Show the animated character
            messageBox.style.display = 'block'; // Show the message box

            // Add the shake animation to the message box
            messageBox.classList.add('shake-element');

            // Send the form data to the server using AJAX
            fetch('/ui/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    'username': username,
                    'password': password,
                }),
            })
            .then(response => response.json())
            .then(data => console.log(data));
        } else {
            // If username or password fields are empty, show this message
            messageText.style.display = 'block';
            messageText.textContent = 'Please enter both username and password.';
            // Do not show the animated character if the credentials are not entered
            animatedCharacter.style.display = 'none';
        }
    });
});