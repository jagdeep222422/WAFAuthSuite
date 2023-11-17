<!-- // We need to use sessions, so you should always start sessions using the below code.
// session_start();
// // If the user is not logged in redirect to the login page...
// if (!isset($_SESSION['loggedin'])) {
// 	header('Location: profile.html');
// 	exit;
// }
// $DATABASE_HOST = 'localhost';
// $DATABASE_USER = 'root';
// $DATABASE_PASS = '';
// $DATABASE_NAME = 'registration';
// $con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
// if (mysqli_connect_errno()) {
// 	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
// }
// // We don't have the password or email info stored in sessions, so instead, we can get the results from the database.
// $stmt = $con->prepare('SELECT username,password, email FROM accounts WHERE id = ?');
// // In this case we can use the account ID to get the account info.
// $stmt->bind_param('i', $_SESSION['id']);
// $stmt->execute();
// $stmt->bind_result($password, $email);
// $stmt->fetch();
// $stmt->close(); -->





<!-- $username = $_SESSION['username']; // Replace 'username' with the actual session key you use

// ... rest of your code ...

$stmt = $con->prepare("SELECT * FROM accounts WHERE username=?");
$stmt->bind_param('s', $username);
$stmt->execute();
$email = "";
$stmt->bind_result($password, $email);
$stmt->fetch();
$stmt->close(); -->
<?php
// We need to use sessions, so you should always start sessions using the below code.
session_start();
// If the user is not logged in redirect to the login page...
// if (!isset($_SESSION['loggedin'])) {
// 	header('Location: index.html');
// 	exit;
// }

// We don't have the password or email info stored in sessions, so instead, we can get the results from the database.
$username = $_SESSION['username']; 
$email = $_SESSION['email']; 
$stmt = $con->prepare("SELECT * FROM accounts WHERE username=?");
$stmt->bind_param('s', $username);
$stmt->execute();
//$email = "";
$stmt->bind_result($password, $email);
$stmt->fetch();
$stmt->close();
?>

<?php
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'root';
$DATABASE_PASS = '';
$DATABASE_NAME = 'wafauthsuite';
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if (mysqli_connect_errno()) {
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}

// SQL query to retrieve data from the 'users' table
$query = "SELECT * FROM accounts";

// Execute the query
$result = mysqli_query($connection, $query);

// Check for query execution errors
if (!$result) {
    die('Query failed: ' . mysqli_error($connection));
}

// Display the retrieved data
while ($row = mysqli_fetch_assoc($result)) {
    echo 'Name: ' . $row['name'] . '<br>';
    echo 'Email: ' . $row['email'] . '<br>';
    // Add more fields as needed
}

// Close the database connection
mysqli_close($connection);
?>