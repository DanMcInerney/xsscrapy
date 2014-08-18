<html>
<body>

Your filtered email address is: <?php echo htmlspecialchars($_POST["email"]); ?>
<br>
Your filtered email address is: <?php echo htmlspecialchars($_POST["email"]); ?>
<br>
Your message: <?php echo str_replace("=", "", $_POST["message"]); ?>
<br>
Your link: <a href=<?php echo $_POST["link"]; ?>>Your Link</a>
<br>
Your cookie: <?php echo $_COOKIE; echo $HTTP_COOKIE_VARS; ?>

</body>
</html>