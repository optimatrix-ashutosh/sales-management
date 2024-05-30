<?php
session_start();

function isAuthenticated() {
    return isset($_SESSION['userId']);
}

function login($username, $password, $conn) {
    $stmt = $conn->prepare("SELECT id, password FROM Users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        $stmt->bind_result($id, $hashed_password);
        $stmt->fetch();
        if (password_verify($password, $hashed_password)) {
            $_SESSION['userId'] = $id;
            return true;
        }
    }
    return false;
}

function logout() {
    session_destroy();
    header("Location: ../views/login.html");
    exit;
}


