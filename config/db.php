<?php

session_start();

$server = "localhost";
$pass = "1001ouo";
$user = "root";
$db = "shopping";

$conn = new mysqli($server,$pass,$user,$db);
if($conn->connect_error){
    die("connect error");
}


?>