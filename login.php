<?php

include_once "config/db.php";

$error = "";

function write_log($message){
    $log_file = __DIR__ . '/config/login_log.txt';
    $date = date("Y-m-d H:i:s");
    $ip = $_SERVER['REMOTE_ADDR']?? 'unknow IP';
    $log_message = "[$date][IP:$ip] $message" . PHP_EOL;
    file_put_contents($log_file, $log_message,FILE_APPEND);
}

try {
    if($_SERVER['REQUEST_METHOD']==="POST"){
        $email = $_POST['email'];
        $password = $_POST['password'];
        $remember = isset($_POST['remember']);

        $sql = "SELECT * FROM users WHERE email = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s",$email);
        $stmt->execute();

        if(!$stmt){
            throw new Exception("Database query failed: " . $conn->error);
        }
        $stmt->bind_param("s",$email);
        $stmt->execute();
        $result = $stmt->get_result();

       if($result->num_rows === 1){
        $user = $result->fetch_assoc();

        if(password_verify($password,$user['password'])){
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user'] = $user['name'];
            $_SESSION['role'] = $user['role'];

            if($remember){
                $selector = bin2hex(random_bytes(32));
                $validator = bin2hex(random_bytes(32));
                $hashed_validator = hash('sha256',$validator);
                $expiry = date("Y-m-d H:i:s", time() + (7 * 24 * 60 * 60));

                $sql = "INSERT INTO user_tokens (user_id, selector, hashed_validator, expires_at) VALUES(?,?,?,?)";
                $stmt_token = $conn->prepare($sql);
                $stmt_token->bind_param("isss",$user['id'],$selector,$hashed_validator,$expiry);
                $stmt_token->execute();
                
                setcookie("remember_me",$selector. ":".$validator,['expires' => time() + 7 *24 * 60 *60, 'path' => '/', 'httponly' => true, 'secure' => isset($_SERVER['HTTPS']),'samesite' => 'Lax']); 
            }

            write_log("Login Success: User Email {$user['email']} logged in successfully. Role: {$user['role']}");

            switch($user['role']){
                case "admin":
                    header("Location: admin_dashboard.php");
                    exit();
                default:
                    header("Location: index.php");
                    exit();
            }
            exit;
         }else{
            $error = "invalid password";
            write_log("Login failed: Incorrect password for email $email");
         }
       }else{
        $error = "no account found with that email";
        write_log("login failed:no account found for email $email");
       }
    }
}catch(Exception $e){
    $error = "An error occurred.Please try again later.";
    write_log("Error: " . $e->getMessage());
}


?>

<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 — 示例</title>
<style>
:root{font-family:system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial;color:#222}
body{display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f3f4f6;margin:0}
.card{background:#fff;padding:24px;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,0.06);width:100%;max-width:420px}
h1{font-size:20px;margin:0 0 8px}
p.lead{margin:0 0 18px;color:#555}
label{display:block;margin-bottom:6px;font-size:13px}
input[type="email"],input[type="password"]{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:14px}
.row{display:flex;gap:12px;align-items:center}
.checkbox{display:flex;align-items:center;gap:8px}
.actions{display:flex;justify-content:space-between;align-items:center;margin-top:14px}
button{background:#0ea5e9;border:none;color:#fff;padding:10px 14px;border-radius:8px;cursor:pointer}
.error{background:#fee2e2;color:#991b1b;padding:10px;border-radius:8px;margin-bottom:12px}
.small{font-size:13px;color:#555}
.muted{color:#6b7280}
a.link{color:#0ea5e9;text-decoration:none}
.show-pass{font-size:13px;color:#374151;cursor:pointer}
@media (max-width:480px){.card{margin:16px}}
</style>
</head>
<body>
<main class="card" role="main" aria-labelledby="loginTitle">
<h1 id="loginTitle">登录到你的账户</h1>
<p class="lead">使用你的邮箱和密码登录。</p>


<?php if(!empty($error)): ?>
<div class="error" role="alert"><?php echo htmlspecialchars($error, ENT_QUOTES); ?></div>
<?php endif; ?>


<form method="post" action="" novalidate>
<div style="margin-bottom:12px">
<label for="email">邮箱</label>
<input id="email" name="email" type="email" required autocomplete="email" placeholder="you@example.com">
</div>


<div style="margin-bottom:6px">
<label for="password">密码</label>
<div class="row">
<input id="password" name="password" type="password" required autocomplete="current-password" placeholder="你的密码">
<button type="button" class="show-pass" id="togglePass" aria-pressed="false">显示</button>
</div>
</div>


<div class="row" style="margin-top:10px;margin-bottom:2px;align-items:center">
<label class="checkbox"><input type="checkbox" name="remember" id="remember"> <span class="small">记住我（7 天）</span></label>
<div style="margin-left:auto" class="muted small"> <a class="link" href="forgot_password.php">忘记密码？</a></div>
</div>


<div class="actions">
<div class="small muted">尚无账号？ <a class="link" href="register.php">注册</a></div>
<button type="submit">登录</button>
</div>
</form>


<p style="margin-top:12px;font-size:12px;color:#6b7280">安全建议：使用 HTTPS, 将 HttpOnly cookie 与安全的 token 存储在服务端。</p>
</main>


<script>
// 简单客户端增强：切换密码可见性 & 基本表单校验提示
const toggle = document.getElementById('togglePass');
const pwd = document.getElementById('password');
toggle.addEventListener('click', ()=>{
const isPwd = pwd.type === 'password';
pwd.type = isPwd ? 'text' : 'password';
toggle.textContent = isPwd ? '隐藏' : '显示';
toggle.setAttribute('aria-pressed', String(isPwd));
});


// 浏览器原生校验不通过时显示友好提示
const form = document.querySelector('form');
form.addEventListener('submit', (e)=>{
if(!form.checkValidity()){
e.preventDefault();
// 简单聚焦第一个无效字段
const firstInvalid = form.querySelector(':invalid');
if(firstInvalid) firstInvalid.focus();
}
});
</script>
</body>
</html>
