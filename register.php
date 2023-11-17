<?php
// Change this to your connection info.
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'root';
$DATABASE_PASS = '';
$DATABASE_NAME = 'wafauthsuite';

// Try and connect using the info above.
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);

// Check connection
if (mysqli_connect_errno()) {
    exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}

// Check if the data was submitted
if (!isset($_POST['username'], $_POST['password'], $_POST['email'])) {
    exit('Please complete the registration form!');
}

// Check for empty values
if (empty($_POST['username']) || empty($_POST['password']) || empty($_POST['email'])) {
    exit('Please complete the registration form');
}

// Validate username and email
if (preg_match('/^[a-zA-Z0-9]+$/', $_POST['username']) == 0) {
    exit('Username is not valid!');
}

if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
    exit('Email is not valid!');
}

// Validate password length
if (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5) {
    exit('Password must be between 5 and 20 characters long!');
}

// Check if the account with that username exists.
if ($stmt = $con->prepare('SELECT id, password FROM accounts WHERE username = ?')) {
    // Bind parameters
    $stmt->bind_param('s', $_POST['username']);
    $stmt->execute();
    $stmt->store_result();

    // Check if username already exists
    if ($stmt->num_rows > 0) {
        echo 'Username exists, please choose another!';
    } else {
        // Insert new account
        if ($stmt = $con->prepare('INSERT INTO accounts (username, password, email) VALUES (?, ?, ?)')) {
            // Hash the password
            $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
            // Bind parameters for the INSERT query
            $stmt->bind_param('sss', $_POST['username'], $password, $_POST['email']);
            $stmt->execute();
            echo 'You have successfully registered! You can now login!';
        } else {
            echo 'Could not prepare statement for insertion: ' . $con->error;
        }
    }

    $stmt->close();
} else {
    echo 'Could not prepare statement for SELECT: ' . $con->error;
}

// Close the connection
$con->close();
?>
