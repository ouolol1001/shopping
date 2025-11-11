<?php
session_start();

$server = "localhost";   // 或 localhost:3306
$user = "root";          // MySQL 用户名
$pass = "1001ouo";              // 没有密码时留空
$db = "shopping";        // 数据库名

$conn = new mysqli($server, $user, $pass, $db);

if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}
?>
