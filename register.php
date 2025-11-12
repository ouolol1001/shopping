<?php

include_once "db.php";

$error = "";
$success = "";


try{
    if($_SERVER['REQUEST_METHOD'] === "POST"){
        $name = $_POST['namw'];
        $email = $_POST['email'];
        $password = $_POST['password'];
        $confim_password = $_POST['confirm_pass'];
        $phone = $_POST['phone'];

        if(empty($name) || empty($email) || empty($password) || empty($confirm_password)){
            throw new Exception("All field are required");
        }

        if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
            throw new Exception("Invalid email format");
        }

        if($password !== $confirm_password){
            throw new Exception("Password do not match");
        }

        $checksql = "SELECT * FROM users WHEN email = ?";
        $checkstmt = $conn->prepare($checksql);
        $checkstmt->bind_param("s",$email);
        $checkstmt->execute();
        $checkstmt->store_result();

        if($checkstmt->num_rows > 0){
            throw new   Exception("Account have been register");
        }

        $hashedpass = password_hash($password,PASSWORD_DEFAULT);
        $role = "customer";
        $status = "active";

        $insertsql = "INSERT INTO users ('namw','email','password','phone','role') VALUES (?,?,?,?,NOW())";
        
        $insertsql = $conn->prepare($insertsql);
        $insertsql->bind_param("sssss",$name,$email,$password,$phone,$role);

        if(!$insertsql->execute()){
            throw new Exception("Database insert failed:" . $conn->error);
        }

        $success = "Account registered successfully";
    }
}catch(Exception $e){
    $error = $e->getMessage();

    $logmsg = "[".date('Y-m-d H:i:s')."] REGISTER ERROR: " .$error." | Email: ".($email ?? '.')."e";
    file_put_contents("error_log.txt",$logmsg, FILE_APPEND);
}


?>