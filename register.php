<?php

include_once __DIR__ ."/config/db.php";

$error = "";
$success = "";


function write_log($message){
    $log_file = __DIR__ . '/config/login_log.txt';
    $date = date("Y-m-d H:i:s");
    $ip = $_SERVER['REMOTE_ADDR']?? 'unknown IP';
    $log_message = "[$date][IP: $ip] $message" . PHP_EOL;
    file_put_contents($log_file, $log_message, FILE_APPEND);
}

if(!isset($_SESSION['user_id']) && isset($_COOKIE['remember_me'])){
    list($selector,$validator) = explode(':',$_COOKIE['remember_me']);
    $sql = "SELECT * FROM user_tokens WHERE selector = ? AND expires_at > NOW()";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param('s',$selector);
    $stmt->execute();
    $result = $stmt->get_result();

    if($result->num_rows === 1){
        $token_row = $result->fetch_assoc();
        if(hash_equals($token_row['hashed_validator'], hash('sha256' ,$validator))){
            $sql = "SELECT * FROM users WHERE id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('i',$token_row['user_id']);
            $stmt->execute();
            $user_result = $stmt->get_result();
            if($user_result->num_rows === 1){
                $user = $user_result->fetch_assoc();
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user'] = $user['name'];
                $_SESSION['role'] = $user['role'];
                write_log("Auto Login Success: User Email {$user['email']} logged in via remember me. Role: {$user['role']}");
                header("Location: index.php");
                exit;
            }else{
                write_log("Auto Login Failed: No user found for user_id {$token_row['user_id']}.");
            }
        }
    }
}


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
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Bootstrap demo</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
  </head>
  <body class="bg-info text-light">
        <div class="container d-flex justify-content-center align-items-center" >
            <div class="card shadow p-4 ">
                <h3 class="text-center mb-4">login</h3>

                <?php if($error):?>
                    <div class="alert  alert-danger" role="alert"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>

                <form action="POST">
                    <div class="mo-3">
                        <label for="">Email</label>
                        <input type="email" name="email" class="form-control" required>
                    </div>
                     <div class="mo-3">
                        <label for="">Password</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>

                    <div class="form-check mb-3">
                        <input type="checkbox" name="remember_me" class="form-check-input" id="remember_me">
                        <label for="rememberme" class="form-check-label">Remember me</label>
                    </div>

                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>

                <p style="text-align:center; margin-top:10px;">Don't have an account? <a href="register.php">Register here</a></p>
                <p style="text-align:center; margin-top:10px;"><a href="#fpassword.php">Forget password</a></p>
            </div>
        </div>
  </body>
</html>