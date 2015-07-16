<?php
  $RADIUS_DIR = "/var/radius";

  # Fetch HTTP parameters in the GET request
  $token = $_GET["token"];
  $url = $_GET["url"];

  # Read the token data written by the RADIUS server
  $json = file_get_contents("$RADIUS_DIR/tokens/$token.json");
  $sess = json_decode($json, true);
?>

<?php if ($sess) { ?>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="/style.css"/>
    <title>Example captive portal</title>
  </head>
  <body>
    <h1>Example captive portal</h1>
    <p>
      <form action="/authorize.cgi" method="POST">
        <?php if ($url) { ?>
          <input type="hidden" name="url" value="<?php echo $url; ?>"/>
        <?php } ?>
        <input type="hidden" name="token" value="<?php echo $token; ?>"/>
        <button type="submit" name="auth" value="quota">100 MB</button>
	<button type="submit" name="auth" value="slow"/>1 Mbit/s</button>
	<button type="submit" name="auth" value="hour"/>One hour</button>
	<button type="submit" name="auth" value="unlimited"/>Unlimited</button>
      </form>
    </p>
    <p>
      <hr>
      <table class="info">
	<tr><td>User</td><td><?php echo $sess['user']; ?></td></tr>
	<tr><td>Service</td><td><?php echo $sess['service']; ?></td></tr>
      </table>
      <hr>
    </p>
  </body>
</html>
<?php } ?>