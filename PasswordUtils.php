<?php
namespace Security;

defined('PASSWORD_BCRYPT') OR define('PASSWORD_BCRYPT', 1);
defined('PASSWORD_BCRYPT_DEFAULT_COST') OR define('PASSWORD_BCRYPT_DEFAULT_COST', 10);
defined('PASSWORD_DEFAULT') OR define('PASSWORD_DEFAULT', PASSWORD_BCRYPT);
// Note that SHA hashes are not implemented in password_hash() or password_verify() in PHP 5.5
// and are not recommended for use. Recommend only the default BCrypt option
defined('PASSWORD_SHA256') OR define('PASSWORD_SHA256', -1);
defined('PASSWORD_SHA512') OR define('PASSWORD_SHA512', -2);
/**
 * Class PasswordUtils
 * @package Security
 */
class PasswordUtils
{
 CONST BLOWFISH_CHAR_RANGE = './0123456789ABCDEFGHIJKLMONPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    CONST BLOWFISH_CRYPT_SETTING = '$2a$';
    CONST BLOWFISH_CRYPT_SETTING_ALT = '$2y$'; // Available from PHP 5.3.7
    CONST BLOWFISH_ROUNDS = 10;
    CONST BLOWFISH_NAME = 'bcrypt';

    // Note that SHA hashes are not implemented in password_hash() or password_verify() in PHP 5.5
    // and are not recommended for use. Recommend only the default BCrypt option
    CONST SHA256_CHAR_RANGE = './0123456789ABCDEFGHIJKLMONPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    CONST SHA256_CRYPT_SETTING = '$5$';
    CONST SHA256_ROUNDS = 5000;
    CONST SHA256_NAME = 'sha256';

    CONST SHA512_CHAR_RANGE = './0123456789ABCDEFGHIJKLMONPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    CONST SHA512_CRYPT_SETTING = '$6$';
    CONST SHA512_ROUNDS = 5000;
    CONST SHA512_NAME = 'sha512';
    CONST DEFAULT_SALT = 'ù%)µ!Oa#?{z£=&2q[Q*}¤';


    /**
     * Default Crypt Algorithm
     *
     * @var INT
     */
    private $algorithm = PASSWORD_BCRYPT;


    /**
     * Name of the current algorithm
     *
     * @var STRING
     */
    private $algoName;


    /**
     * Setting for PHP Crypt function, defines algorithm
     *
     * Default setting is '$2a$' : BCrypt
     *
     * @var STRING
     */
    protected $cryptSetting;


    /**
     * Setting for PHP Crypt function, defines processing cost
     *
     * Default setting is '08$' for BCrypt rounds
     *
     * @var INT
     */
    protected $rounds;


    /**
     * Salt Character Count for Crypt Functions
     *
     * @var INT
     */
    protected $addSaltChars;


    /**
     * Salt Character Range for Crypt Functions
     *
     * @var STRING
     */
    protected $saltCharRange;


    /**
     * Class Constructor
     */
    public function __construct(){
        if (!function_exists('crypt')) 
        {
            trigger_error("Crypt must be loaded for password_hash to function", E_USER_WARNING);
            return null;
        }
        // Initialise default algorithm
        $this->setAlgorithm($this->algorithm);
    }

    /**
     * @param $password
     * @param int $algorithm
     * @param array $options
     * @return bool|mixed|string
     */
    public function PasswordHash($password, $algorithm=PASSWORD_DEFAULT, $options=array())
    {
        isset($options['cost']) OR $options['cost'] = PASSWORD_BCRYPT_DEFAULT_COST;
        $options['cost'] >=4 OR $options['cost'] =4;
        $options['cost'] <=31 OR $options['cost'] =31;

        if (function_exists('password_hash'))
            return password_hash($password,$algorithm,$options);
        $this->setAlgorithm($algorithm);
        $this->setCost($options['cost']);
        $salt = null;
        if(isset($options['salt']) AND !empty($options['salt']))
        {
                for ($i = 0; $i<$this->addSaltChars; $i++)
                {
                    $salt .= $this->saltCharRange[rand(0,(strlen($this->saltCharRange)-1))];
                }
            $salt = $this->cryptSetting.$this->rounds.$salt.'$';
        }
        else
        $salt .= $this->createRandomToken();
        $password = crypt($password, $salt);
        return $password;
    }

    /**
     * @param $password
     * @param $hash
     * @return bool
     */
    public function PasswordVerify($password, $hash)
    {
        if (function_exists('password_verify'))
            return password_verify($password,$hash);
        return crypt($password, $hash) === $hash;
    }

    /**
     * @param $hash
     * @param $algo
     * @param array $options
     * @return bool|string
     */
    public function PasswordNeedsReHash($hash, $algo, $options=array())
    {
        isset($options['cost']) OR $options['cost'] = PASSWORD_BCRYPT_DEFAULT_COST;
        $options['cost'] >=4 OR $options['cost'] =4;
        $options['cost'] <=31 OR $options['cost'] =31;
        if (function_exists('password_needs_rehash'))
            return password_needs_rehash($hash, $algo, $options);
        $this->setAlgorithm($algo);
        $this->setCost($options['cost']);
        $setting = $this->cryptSetting.$this->rounds;
        return !(substr($hash, 0, strlen($setting)) === $setting);
    }

    /**
     * @param $hash
     * @return array|bool
     */
    public function PasswordGetInfos($hash)
    {
        if (function_exists('password_get_info'))
            return password_get_info($hash);
        $params = explode("$", $hash);
        if (count($params) < 4) return FALSE;
        switch ($params['1']){
            case '2a':
            case '2y':
            case '2x':
                $algo = PASSWORD_BCRYPT;
                $algoName = self::BLOWFISH_NAME;
                break;
            case '5':
                $algo = PASSWORD_SHA256;
                $algoName = self::SHA256_NAME;
                break;
            case '6':
                $algo = PASSWORD_SHA512;
                $algoName = self::SHA512_NAME;
                break;
            default:
                return FALSE;
        }
        $cost = preg_replace("/[^0-9,.]/", "", $params['2']);
        return array(
            'algo' => $algo,
            'algoName' => $algoName,
            'options' => array(
                'cost' => $cost
            ),
        );
    }

    /**
     * Salt Character Count
     * @param $count
     * @return $this|bool
     */
    public function addSaltChars($count){
        if (is_int($count))
            $this->addSaltChars = $count;
            return $this;
    }


    /**
     * Salt Character Range
     * @param $chars
     * @return $this|bool
     */
    public function saltCharRange($chars)
    {
        if (is_string($chars))
            $this->saltCharRange = $chars;
            return $this;
    }

    /**
     * @param int $length
     * @param bool|false $raw
     * @return string
     */
    public function createRandomToken($length = 32,$raw=true)
    {
        if(!isset($length) || intval($length) <= 8 )
            $length = 32;
        $length = intval($length);
        $output = null;
        if (function_exists('random_bytes'))
            return 	($raw === false) ? bin2hex(random_bytes($length)):random_bytes($length);
        if (function_exists('openssl_random_pseudo_bytes')  and version_compare(PHP_VERSION, '5.3.7', '>='))
        {
            $output = openssl_random_pseudo_bytes($length, $cstrong);
            if($output AND $cstrong) return ($raw === false) ? bin2hex($output):$output;
        }
        do
        {
            //some entropy, but works ^^
            $weakEntropy = array(
                serialize($_ENV),
                serialize(stat(__FILE__)),
                __DIR__,
                file_exists('/dev/urandom') ? fread(fopen('/dev/urandom', 'rb'), 64) : str_repeat("\x00", 64),
                PHP_OS,
                microtime(),
                (string) lcg_value(),
                (string) PHP_MAXPATHLEN,
                PHP_SAPI,
                (string) PHP_INT_MAX .'.'.PHP_INT_SIZE,
                serialize($_SERVER),
                serialize(get_defined_constants()),
                get_current_user(),
                serialize(ini_get_all()),
                (string) memory_get_usage().'.'.memory_get_peak_usage(),
                php_uname(),
                phpversion(),
                extension_loaded('gmp') ? gmp_strval(gmp_random(4)):microtime(),
                zend_version(),
                (string) getmypid(),
                (string) getmyuid(),
                (string) mt_rand(),
                (string) getmyinode(),
                (string) getmygid(),
                (string) rand(),
                function_exists('zend_thread_id') ? ((string) zend_thread_id()):microtime(),
                var_export(@get_browser(), true),
                function_exists('getrusage') ? @implode(getrusage()):microtime(),
                function_exists('sys_getloadavg') ? @implode(sys_getloadavg()):microtime(),
                serialize(get_loaded_extensions()),
                sys_get_temp_dir(),
                (string) disk_free_space('.'),
                function_exists('posix_times')? serialize(posix_times()) : microtime(),
                (string) disk_total_space('.'),
                uniqid(microtime(),true),
                file_exists('/proc/cpuinfo') ? file_get_contents('/proc/cpuinfo') : microtime(),
            );
            shuffle($weakEntropy);
            $entropy = hash('sha512', implode($weakEntropy), true);
            foreach($weakEntropy as $k => $c)
            { //mixing entropy values with XOR and hash randomness extractor
                $entropy ^= hash('sha256', $c . microtime() . $k, true) . hash('sha256', mt_rand() . microtime() . $k . $c, true);
                $entropy ^= hash('sha512', ((string) lcg_value()) . $c . microtime() . $k, true);
            }
            unset($weakEntropy);
            $output .= substr($entropy, 0, min($length - strlen($output), $length));
            unset($entropy);
        }while(!isset($output{$length - 1}));
	return ($raw === false) ? bin2hex($output):$output;
}

    /**
     * Set Crypt Algorithm
     * @param null $algo
     * @return $this
     */
    public function setAlgorithm($algo=NULL){
        switch ($algo){
            case PASSWORD_SHA256:
                $this->algorithm = PASSWORD_SHA256;
                $this->cryptSetting =self::SHA256_CRYPT_SETTING;
                $this->setCost(self::SHA256_ROUNDS);
                $this->addSaltChars(16);
                $this->saltCharRange(self::SHA256_CHAR_RANGE);
                $this->algoName = self::SHA256_NAME;
                break;
            case PASSWORD_SHA512:
                $this->algorithm = PASSWORD_SHA512;
                $this->cryptSetting = self::SHA512_CRYPT_SETTING;
                $this->setCost(self::SHA512_ROUNDS);
                $this->addSaltChars(16);
                $this->saltCharRange(self::SHA512_CHAR_RANGE);
                $this->algoName = self::SHA512_NAME;
                break;
            case PASSWORD_BCRYPT:
            default:
                $this->algorithm = PASSWORD_BCRYPT;
            // Use improved Blowfish algorithm if supported
                if (version_compare(PHP_VERSION, '5.3.7') >= 1)
                    $this->cryptSetting =self::BLOWFISH_CRYPT_SETTING_ALT;
                else
                    $this->cryptSetting =self::BLOWFISH_CRYPT_SETTING;
                $this->setCost(self::BLOWFISH_ROUNDS);
                $this->addSaltChars(22);
                $this->saltCharRange(self::BLOWFISH_CHAR_RANGE);
                $this->algoName = self::BLOWFISH_NAME;
                break;
        }
        return $this;
    }

    /**
     * Set Cost
     * @param $rounds
     * @return $this
     */
    private function setCost($rounds)
    {
        switch ($this->algorithm){
            case PASSWORD_BCRYPT:
                $this->rounds = $this->setBlowfishCost($rounds);
                break;
            case PASSWORD_SHA256:
            case PASSWORD_SHA512:
                $this->rounds = $this->setShaCost($rounds);
                break;
        }
        return $this;
    }


    /**
     * Set Blowfish hash cost
     *
     * Minimum 4, maximum 31. Value is base-2 log of actual number of rounds, so
     * 4 = 16, 8 = 256, 16 = 65,536 and 31 = 2,147,483,648
     * Defaults to 8 if value is out of range or incorrect type
     * @param $rounds
     * @return string
     */
    private function setBlowfishCost($rounds)
    {
        if (!is_int($rounds) || $rounds < 4 || $rounds > 31)
            $rounds = $rounds = self::BLOWFISH_ROUNDS;
        return sprintf("%02d", $rounds)."$";
    }

    /**
     * Set SHA hash cost
     *
     * Minimum 1000, maximum 999,999,999
     * Defaults to 5000 if value is out of range or incorrect type
     * @param $rounds
     * @return string
     */
    private function setShaCost($rounds){
        if (!is_int($rounds) || $rounds < 1000 || $rounds > 999999999){
            switch ($this->algorithm){
                case PASSWORD_SHA256:
                    $rounds = self::SHA256_ROUNDS;
                    break;
                default:
                    $rounds = self::SHA512_ROUNDS;
            }
        }
        return "rounds=" . $rounds ."$";
    }

}
