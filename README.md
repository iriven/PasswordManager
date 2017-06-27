# PasswordUtils
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=XDCFPNTKUC4TU)

A PHP password protection Library. This library is intended to provide forward compatibility with the [password_*](http://php.net/password)  functions that ship with PHP 5.5.

## Usage:

#### Installation And Initialisation

To utilize PasswordUtils, first import and require PasswordUtils.php file in your project.
##### Installation
```php
require_once 'PasswordUtils.php';
```
##### Initialisation
```php
$Encryption = new \Security\PasswordUtils();
```
**Creating Password Hashes**

To create a password hash from a password, simply use the `password_hash` function.
````PHP
    $hashedPassword = $Encryption->PasswordHash($password, PASSWORD_BCRYPT);
    
    /**
    Note that the algorithm that we chose is `PASSWORD_BCRYPT`. That's the current strongest algorithm supported. This is the `BCRYPT` crypt algorithm. It produces a 60 character hash as the result. `BCRYPT` also allows for you to define a `cost` parameter in the options array. This allows for you to change the CPU cost of the algorithm. The cost can range from `4` to `31`. I would suggest that you use the highest cost that you can, while keeping response time reasonable 
    */
    
    $hashedPassword = $Encryption->PasswordHash($password, PASSWORD_BCRYPT,['cost' => 12]);
````
Another algorithm name is supported:
````PHP
    PASSWORD_DEFAULT
````
