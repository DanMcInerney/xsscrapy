<?php
setcookie("user", "JohnDoe", time() + 3600, "/");
?>

<html>
<body>
<form method="post" action="reflect.php">
  Email: <input name="email" type="text" /><br>
  Message:<br>
  <textarea name="message" rows="15" cols="40">
  </textarea><br>
  Link: <input name="link", type="text" /><br>
  <input type="submit" />
</form>

</body>
</html>
