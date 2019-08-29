# Password
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=XDCFPNTKUC4TU)

A PHP password protection and verification Library. This library is intended to provide forward compatibility with the [password_*](http://php.net/password)  functions that ship with PHP 5.5.

## Usage:

#### Installation And Initialisation

To utilize PasswordUtils, first import and require PasswordUtils.php file in your project.
##### Installation
```php
require_once 'Password.php';
```
##### Initialisation
```php
$Encryption = new \Security\PasswordManager();
```
#### Creating Password Hashes

To create a password hash from a password, simply use the `PasswordHash` method
````PHP
    $hashedPassword = $Encryption->PasswordHash($password, PASSWORD_BCRYPT);
````   
Note that the algorithm that we chose is `PASSWORD_BCRYPT`. That's the current strongest algorithm supported. 
This is the `BCRYPT` crypt algorithm. It produces a 60 character hash as the result. `BCRYPT` also allows for 
you to define a `cost` parameter in the options array. This allows for you to change the CPU cost of the algorithm. 
The cost can range from `4` to `31`. I would suggest that you use the highest cost that you can, while keeping response time reasonable 
````PHP
    $hashedPassword = $Encryption->PasswordHash($password, PASSWORD_BCRYPT,['cost' => 12]);
````

Another algorithm name is supported:
````PHP
    PASSWORD_DEFAULT
````
This will use the strongest algorithm available to PHP at the current time. Presently, this is the same as 
specifying `PASSWORD_BCRYPT`. But in future versions of PHP, it may be updated to use a stronger algorithm 
if one is introduced. It can also be changed if a problem is identified with the BCRYPT algorithm. Note that 
if you use this option, you are **strongly** encouraged to store it in a `VARCHAR(255)` column to avoid 
truncation issues if a future algorithm increases the length of the generated hash.

There are two other algorithm implemented in this class:
````PHP
PASSWORD_SHA256  and  PASSWORD_SHA512
````
Note that SHA hashes are not implemented in password_hash() or password_verify() in PHP 5.5 and are not recommended 
for use. Recommend only the default BCrypt option in production environment.

#### Verifying Password Hashes

It is very important that you should check the return value of "PasswordHash" method prior to storing it, because "false" or "null" may be returned if it encountered an error.
To verify a hash created by "PasswordHash", simply call:

````PHP
	if ($Encryption->PasswordVerify($password, $hashedPassword)){
	// Valid : store in DB or Continue login process
	} 
    	else {
	// Invalid: display error
	}
````
#### Rehashing Passwords

From time to time you may update your hashing parameters (algorithm, cost, etc). So a function to determine if rehashing is necessary is available:

````PHP
    if ($Encryption->PasswordVerify($password, $hashedPassword)){
    		if ($Encryption->PasswordNeedsReHash($hashedPassword, $algorithm, $options))
		{
			$hash = $Encryption->PasswordHash($password, $algorithm, $options);
			/* Store new hash in db */
		}
	}
````
## Authors

* **Alfred TCHONDJO** - *Project Initiator* - [iriven France](https://www.facebook.com/Tchalf)

## License

This project is licensed under the GNU General Public License V3 - see the [LICENSE](LICENSE) file for details

## Donation

If this project help you reduce time to develop, you can give me a cup of coffee :)

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=XDCFPNTKUC4TU)

## Disclaimer

If you use this library in your project please add a backlink to this page by this code.

```html

<a href="https://github.com/iriven/Password" target="_blank">This Project Uses Alfred's TCHONDJO Password Library.</a>
```
## Issues Repport
Repport issues [Here](https://github.com/iriven/Password/issues)
