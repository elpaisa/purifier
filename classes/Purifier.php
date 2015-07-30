<?php

/**
 * Copyright © 2015, Graphics Inc. Colombia
 * clientes@desarrollowebmedellin.com
 * www.desarrollowebmedellin.com
 *
 * @author  John L. Diaz.
 * @created 12/3/13 9:58 PM
 */
class Purifier
{

    /**
     * Sha encryption method
     *
     * @var string
     */
    public static $PBKDF2_HASH_ALGORITHM = "sha256";

    /**
     * Number of time to encrypt the string
     *
     * @var int
     */
    public static $PBKDF2_ITERATIONS = 1000;

    /**
     * Salt size
     *
     * @var int
     */
    public static $PBKDF2_SALT_BYTE_SIZE = 24;

    /**
     * Byte size
     *
     * @var int
     */
    public static $PBKDF2_HASH_BYTE_SIZE = 24;

    /**
     * Number of sections to split the hash
     *
     * @var int
     */
    public static $HASH_SECTIONS = 4;

    /**
     * @var int
     */
    public static $HASH_ALGORITHM_INDEX = 0;

    /**
     * @var int
     */
    public static $HASH_ITERATION_INDEX = 1;

    /**
     * @var int
     */
    public static $HASH_SALT_INDEX = 2;

    /**
     * @var int
     */
    public static $HASH_PBKDF2_INDEX = 3;

    /**
     * Filter data with given configuration
     *
     * @created 01/01/2014
     *
     * @param type $obj - object with string and filters
     *
     * @return boolean
     */
    public static function filterDataValue($obj)
    {
        if (is_object($obj)) {
            if (isset($obj->string) && $obj->string != '') {
                $stringValue = $obj->string;
                if (isset($obj->filters) && is_array($obj->filters)) {
                    foreach ($obj->filters as $filterFunction => $filterArgs) {
                        if (is_callable($filterFunction)) {
                            //put the string to be filtered at the top of the array
                            array_unshift($filterArgs, $stringValue);
                            $stringValue = call_user_func_array($filterFunction, $filterArgs);
                        }
                    }
                }

                return $stringValue;
            }

            return false;
        }

        return false;
    }

    /**
     * Create an object with the string and the config array
     *
     * @created 01/01/2014
     *
     * @param string $string
     * @param array  $filterArray
     *
     * @return bool|stdClass
     */
    public static function prepareDataObject($string, $filterArray = array())
    {
        if (isset($string) && $string != '') {
            $objNew          = new stdClass();
            $objNew->string  = $string;
            $objNew->filters = array(
                'strip_tags'       => array(),
                'addslashes'       => array(),
                'htmlspecialchars' => array(ENT_QUOTES)
            );
            if (count($filterArray) > 0) {
                $objNew->filters = $filterArray;
            }

            return $objNew;
        }

        return false;
    }

    /**
     * Filters XSS for GET, POST and REQUEST
     *
     * @created 01/01/2014
     *
     * @param array $filterVarArray
     * @param array $skipArray
     *
     * @return array|bool
     */
    public function filterXSS($filterVarArray, $skipArray = array())
    {
        if (is_array($filterVarArray) && count($filterVarArray) > 0) {
            foreach ($filterVarArray as $gKey => $gValue) {
                if (!in_array($gKey, $skipArray)) {
                    if ($gValue != '' && !is_array($gValue) && !is_object($gValue)) {
                        $objectString          = self::prepareDataObject(
                            $gValue,
                            array('htmlspecialchars' => array(ENT_QUOTES))
                        );
                        $filterVarArray[$gKey] = self::filterDataValue($objectString);
                    }
                }
            }

            return $filterVarArray;
        }

        return false;
    }

    /**
     * Determines the filter constant based on the given string
     *
     * @created 01/01/2014
     *
     * @param string $type
     * @param bool   $validate
     *
     * @return array
     */
    private function getType($type, $validate)
    {
        $return = array('constant', 'flags' => null);
        switch ($type) {
            case'string':
                $return['constant'] = FILTER_SANITIZE_STRING;
                //$return['flags']    = FILTER_FLAG_ENCODE_AMP;
                break;
            case'int':
                $return['constant'] = ($validate ? FILTER_VALIDATE_INT : FILTER_SANITIZE_NUMBER_INT);
                break;
            case'url':
                $return['constant'] = ($validate ? FILTER_VALIDATE_URL : FILTER_SANITIZE_URL);
                break;
            case'email':
                $return['constant'] = ($validate ? FILTER_VALIDATE_EMAIL : FILTER_SANITIZE_EMAIL);
                break;
            case'float':
                $return['constant'] = ($validate ? FILTER_VALIDATE_FLOAT : FILTER_SANITIZE_NUMBER_FLOAT);
                break;
            case'ip':
                $return['constant'] = FILTER_VALIDATE_IP;
                break;
            case'bool':
                $return['constant'] = FILTER_VALIDATE_BOOLEAN;
                break;
            default:
                $return['constant'] = FILTER_UNSAFE_RAW;
        }

        return $return;
    }

    /**
     * Sanitize the variable
     *
     * @param string|array $string String to be sanitized
     * @param string       $type
     * @param bool         $validate
     *
     * @return bool|mixed|string
     */
    public function getVar($string, $type = null, $validate = false)
    {

        if ($type === 'array' && is_array($string)) {
            return filter_var_array($string, FILTER_SANITIZE_STRING);
        }

        $objectString = self::prepareDataObject($string, array('htmlspecialchars' => array(ENT_QUOTES)));
        $sanitized    = self::filterDataValue($objectString);

        if (isset($type) && $type !== 'array') {
            $sanitizeType = $this->getType($type, $validate);
            $sanitized    = filter_var($sanitized, $sanitizeType['constant'], $sanitizeType['flags']);
        }

        return ($type === 'int' ? (int) $sanitized : $sanitized);
    }

    /**
     * Gets safely the given input var
     *
     * @param string $varName
     * @param string $type
     * @param bool   $validate
     * @param bool   $utf8Encode
     * @param string $defaultValue
     *
     * @return bool|mixed|null|string|array
     */
    public function getInputVar(
        $varName,
        $type = 'string',
        $validate = false,
        $utf8Encode = false,
        $defaultValue = null
    ) {

        $postRequest = (isset($_POST) ? $_POST : array());
        $getRequest  = (isset($_GET) ? $_GET : array());
        $request     = (isset($_REQUEST) ? $_REQUEST : array());


        $var = null;
        if (isset($request[$varName])) {
            $var = $request[$varName];
        } else {
            if (isset($getRequest[$varName])) {
                $var = $getRequest[$varName];
            } else {
                if (isset($postRequest[$varName])) {
                    $var = $postRequest[$varName];
                } else {
                    return $defaultValue;
                }
            }
        }

        if (is_array($var)) {

            if ($type === 'int') {
                return false;
            }

            $var = array_map(
                function ($value) use ($type, $validate) {
                    return $this->getVar($value, $type, $validate);
                },
                $var
            );

            return array_unique($var);
        }

        if ($type !== 'array') {
            $var = trim($var);
        }
        if ($utf8Encode) {
            $var = utf8_encode($var);
        }

        return $this->getVar($var, $type, $validate);
    }

    /**
     * @return mixed
     */
    public function getRequestMethod()
    {
        return $_SERVER['REQUEST_METHOD'];
    }

    /**
     * Cleans some string to be used as filename
     *
     * @param string $str the string to be cleaned
     * @param bool   $useTransLiteration
     * @param array  $replace
     * @param string $delimiter
     *
     * @return string
     */
    public function cleanString($str, $useTransLiteration = false, $replace = array(), $delimiter = '_')
    {
        setlocale(LC_ALL, 'en_US.UTF8');

        if (!empty($replace)) {
            $str = str_replace((array) $replace, ' ', $str);
        }

        if ($useTransLiteration) {
            if (function_exists('transliterator_transliterate')) {
                $str = transliterator_transliterate('Accents-Any', $str);
            } else {
                $str = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $str);
            }
        }

        $str = strtr(
            $str,
            "ÀÂÁáàâÔÒÓóôòÊÈÉéèêÍÎÌíîìÛÙÚúûùŷÑñ",
            "AAAaaaOOOoooEEEeeeIIIiiiUUUuuuyNn"
        );


        $str = preg_replace("/[^a-zA-Z0-9@\.\/_|+ -](\.)?/is", '', $str);
        $str = strtolower(trim($str, '-'));
        $str = preg_replace("/[\/|+ -]+/", $delimiter, $str);
        $str = str_replace(array('"', "'", "/", "\\"), "", $str);
        $str = strip_tags($str);

        if (strpos($str, '.') === 0) {
            $str = time() . $str;
        }

        return trim($str);
    }

    /**
     * Generates a secure password
     *
     * @param $length
     *
     * @return string
     */
    public static function genSecurePassword($length)
    {
        $sChars  = "abcdefghjmnpqrstuvwxyz234567890?$=+@&#ABCDEFGHJKLMNPQRSTUVWYXZ";
        $iLength = strlen($sChars) - 1;
        $key     = '';

        for ($i = 0; $i < $length; $i++) {
            $key .= $sChars[mt_rand(0, $iLength)];
        }

        return ($key);
    }

    /**
     * Generates a unique key hash
     *
     * @return string
     */
    public static function genKey()
    {
        $hash = self::genSecurePassword(16);
        $hash = sha1($hash . time()) . md5($hash . time());

        return ($hash);
    }

    /**
     * Encrypts a string into a secure password with random salts
     *
     * @param string $password
     *
     * @return string
     */
    public function encryptPassword($password)
    {
        // Using the format: algorithm:iterations:salt:hash
        $salt = base64_encode(mcrypt_create_iv(self::$PBKDF2_SALT_BYTE_SIZE, MCRYPT_DEV_URANDOM));

        $password = self::$PBKDF2_HASH_ALGORITHM . ":" . self::$PBKDF2_ITERATIONS . ":" . $salt . ":" .
            base64_encode(
                $this->pbkdf2(
                    self::$PBKDF2_HASH_ALGORITHM,
                    $password,
                    $salt,
                    self::$PBKDF2_ITERATIONS,
                    self::$PBKDF2_HASH_BYTE_SIZE,
                    true
                )
            );

        return $password;
    }

    /**
     * Validates the password against the current salt encryption
     *
     * @param string $password
     * @param string $correctHash
     *
     * @return bool
     */
    public function validatePassword($password, $correctHash)
    {
        $params = explode(":", $correctHash);

        if (count($params) < self::$HASH_SECTIONS) {
            return false;
        }
        $pbkdf2 = base64_decode($params[self::$HASH_PBKDF2_INDEX]);

        $valid = $this->slowEquals(
            $pbkdf2,
            $this->pbkdf2(
                $params[self::$HASH_ALGORITHM_INDEX],
                $password,
                $params[self::$HASH_SALT_INDEX],
                (int) $params[self::$HASH_ITERATION_INDEX],
                strlen($pbkdf2),
                true
            )
        );

        return $valid;
    }

    /**
     * Compares two strings $a and $b in length-constant time.
     *
     * @param string $a
     * @param string $b
     *
     * @return bool
     */
    public function slowEquals($a, $b)
    {
        $diff = strlen($a) ^ strlen($b);
        for ($i = 0; $i < strlen($a) && $i < strlen($b); $i++) {
            $diff |= ord($a[$i]) ^ ord($b[$i]);
        }

        return $diff === 0;
    }

    /**
     * PBKDF2 key derivation function as defined by RSA's PKCS #5: https://www.ietf.org/rfc/rfc2898.txt
     * $algorithm - The hash algorithm to use. Recommended: SHA256
     * $password - The password.
     * $salt - A salt that is unique to the password.
     * $count - Iteration count. Higher is better, but slower. Recommended: At least 1000.
     * $keyLength - The length of the derived key in bytes.
     * $rawOutput - If true, the key is returned in raw binary format. Hex encoded otherwise.
     * Returns: A $keyLength-byte key derived from the password and salt.
     *
     * Test vectors can be found here: https://www.ietf.org/rfc/rfc6070.txt
     *
     * This implementation of PBKDF2 was originally created by https://defuse.ca
     * With improvements by http://www.variations-of-shadow.com
     *
     * @param string $algorithm sha256
     * @param string $password
     * @param string $salt
     * @param int    $count
     * @param int    $keyLength
     * @param bool   $rawOutput
     *
     * @return string
     */
    private function pbkdf2($algorithm, $password, $salt, $count, $keyLength, $rawOutput = false)
    {
        $algorithm = strtolower($algorithm);
        if (!in_array($algorithm, hash_algos(), true)) {
            trigger_error('PBKDF2 ERROR: Invalid hash algorithm.', E_USER_ERROR);
        }
        if ($count <= 0 || $keyLength <= 0) {
            trigger_error('PBKDF2 ERROR: Invalid parameters.', E_USER_ERROR);
        }

        if (function_exists("hash_pbkdf2")) {
            // The output length is in NIBBLES (4-bits) if $rawOutput is false!
            if (!$rawOutput) {
                $keyLength = $keyLength * 2;
            }

            return hash_pbkdf2($algorithm, $password, $salt, $count, $keyLength, $rawOutput);
        }

        $hash_length = strlen(hash($algorithm, "", true));
        $blockCount  = ceil($keyLength / $hash_length);

        $output = "";
        for ($i = 1; $i <= $blockCount; $i++) {
            // $i encoded as 4 bytes, big endian.
            $last = $salt . pack("N", $i);
            // first iteration
            $last = $xorSum = hash_hmac($algorithm, $last, $password, true);
            // perform the other $count - 1 iterations
            for ($j = 1; $j < $count; $j++) {
                $xorSum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }
            $output .= $xorSum;
        }

        if ($rawOutput) {
            return substr($output, 0, $keyLength);
        } else {
            return bin2hex(substr($output, 0, $keyLength));
        }
    }

    /**
     * Cleans a string of charset specific characters to be used as url valid string
     *
     * @param $string
     * @param $charset
     *
     * @return mixed
     */
    public function charsetClean($string, $charset)
    {
        if ($charset == 'utf-8') {
            $search  = array(
                '@<script[^>]*?>.*?</script>@si', // Strip out javascript
                '@<[\/\!]*?[^<>]*?>@si', // Strip out HTML tags
                '@([\r\n])[\s]+@', // Strip out white space
                '@&(quot|#34);@i', // Replace HTML entities
                '@&(amp|#38);@i',
                '@&(lt|#60);@i',
                '@&(gt|#62);@i',
                '@&(nbsp|#160);@i',
                '@&(iexcl|#161);@i',
                '@&(cent|#162);@i',
                '@&(pound|#163);@i',
                '@&(copy|#169);@i',
                '@À@i',
                '@Á@i',
                '@Â@i',
                '@Ã@i',
                '@Ä@i',
                '@Å@i',
                '@à@i',
                '@á@i',
                '@â@i',
                '@ã@i',
                '@ä@i',
                '@å@i',
                '@Ş@i',
                '@ş@i',
                '@Ç@i',
                '@ç@i',
                '@Ò@i',
                '@Ó@i',
                '@Ô@i',
                '@Ô@i',
                '@Ö@i',
                '@Ø@i',
                '@ò@i',
                '@ó@i',
                '@ô@i',
                '@õ@i',
                '@ö@i',
                '@ø@i',
                '@È@i',
                '@É@i',
                '@Ê@i',
                '@Ë@i',
                '@è@i',
                '@é@i',
                '@ê@i',
                '@ë@i',
                '@İ@i',
                '@Ì@i',
                '@Í@i',
                '@Î@i',
                '@Ï@i',
                '@ì@i',
                '@í@i',
                '@î@i',
                '@ï@i',
                '@Ù@i',
                '@Ú@i',
                '@Û@i',
                '@Ü@i',
                '@ù@i',
                '@ú@i',
                '@û@i',
                '@ü@i',
                '@Ñ@i',
                '@ñ@i',
                '@ı@i',
                '@ğ@i'
            );
            $replace = array(
                '',
                '',
                '-',
                '',
                '',
                '',
                '',
                '',
                '',
                '',
                '',
                '',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                'a',
                's',
                's',
                'c',
                'c',
                'o',
                'o',
                'o',
                'o',
                'o',
                'o',
                'o',
                'o',
                'o',
                'o',
                'o',
                'o',
                'e',
                'e',
                'e',
                'e',
                'e',
                'e',
                'e',
                'e',
                'i',
                'i',
                'i',
                'i',
                'i',
                'i',
                'i',
                'i',
                'i',
                'u',
                'u',
                'u',
                'u',
                'u',
                'u',
                'u',
                'u',
                'n',
                'n',
                'i',
                'g'
            );

        } else {
            $search  = array(
                '@<script[^>]*?>.*?</script>@si', // Strip out javascript
                '@<[\/\!]*?[^<>]*?>@si', // Strip out HTML tags
                '@([\r\n])[\s]+@', // Strip out white space
                '@&(quot|#34);@i', // Replace HTML entities
                '@&(amp|#38);@i',
                '@&(lt|#60);@i',
                '@&(gt|#62);@i',
                '@&(nbsp|#160);@i',
                '@&(iexcl|#161);@i',
                '@&(cent|#162);@i',
                '@&(pound|#163);@i',
                '@&(copy|#169);@i',
                '@&#305;@i',
                '@&#351;@i',
                '@&#287;@i',
                '@' . chr(192) . '@i',
                '@' . chr(193) . '@i',
                '@' . chr(194) . '@i',
                '@' . chr(195) . '@i',
                '@' . chr(196) . '@i',
                '@' . chr(197) . '@i',
                '@' . chr(198) . '@i',
                '@' . chr(199) . '@i',
                '@' . chr(200) . '@i',
                '@' . chr(201) . '@i',
                '@' . chr(202) . '@i',
                '@' . chr(203) . '@i',
                '@' . chr(204) . '@i',
                '@' . chr(205) . '@i',
                '@' . chr(206) . '@i',
                '@' . chr(207) . '@i',
                '@' . chr(208) . '@i',
                '@' . chr(209) . '@i',
                '@' . chr(210) . '@i',
                '@' . chr(211) . '@i',
                '@' . chr(212) . '@i',
                '@' . chr(213) . '@i',
                '@' . chr(214) . '@i',
                '@' . chr(216) . '@i',
                '@' . chr(217) . '@i',
                '@' . chr(218) . '@i',
                '@' . chr(219) . '@i',
                '@' . chr(220) . '@i',
                '@' . chr(221) . '@i',
                '@' . chr(223) . '@i',
                '@' . chr(224) . '@i',
                '@' . chr(225) . '@i',
                '@' . chr(226) . '@i',
                '@' . chr(227) . '@i',
                '@' . chr(228) . '@i',
                '@' . chr(229) . '@i',
                '@' . chr(230) . '@i',
                '@' . chr(231) . '@i',
                '@' . chr(232) . '@i',
                '@' . chr(233) . '@i',
                '@' . chr(234) . '@i',
                '@' . chr(235) . '@i',
                '@' . chr(236) . '@i',
                '@' . chr(237) . '@i',
                '@' . chr(238) . '@i',
                '@' . chr(239) . '@i',
                '@' . chr(241) . '@i',
                '@' . chr(242) . '@i',
                '@' . chr(243) . '@i',
                '@' . chr(244) . '@i',
                '@' . chr(245) . '@i',
                '@' . chr(246) . '@i',
                '@' . chr(248) . '@i',
                '@' . chr(249) . '@i',
                '@' . chr(250) . '@i',
                '@' . chr(251) . '@i',
                '@' . chr(252) . '@i',
                '@' . chr(253) . '@i',
                '@' . chr(255) . '@i'
            );
            $replace = array(
                '',
                '',
                '-',
                '',
                '',
                '',
                '',
                '',
                '',
                '',
                '',
                '',
                'i',
                's',
                'g',
                'a',
                'a',
                'a',
                'a',
                'a',
                'aa',
                ($charset == 'windows-1257' ? 'e' : 'ae'),
                'c',
                ($charset == 'windows-1257' ? 'e' : 'c'),
                'e',
                'e',
                'e',
                'i',
                'i',
                'i',
                'i',
                ($charset == 'windows-1257' ? 'd' : 's'),
                'n',
                'o',
                'o',
                'o',
                'o',
                'o',
                ($charset == 'windows-1257' ? 'u' : 'o'),
                'u',
                'u',
                'u',
                'u',
                'y',
                's',
                'a',
                ($charset == 'windows-1257' ? 'i' : 'a'),
                'a',
                'a',
                'a',
                'aa',
                ($charset == 'windows-1257' ? 'e' : 'ae'),
                'c',
                ($charset == 'windows-1257' ? 'c' : 'e'),
                'e',
                'e',
                'e',
                'i',
                'i',
                'i',
                'i',
                'n',
                'o',
                'o',
                'o',
                'o',
                'o',
                ($charset == 'windows-1257' ? 'u' : 'o'),
                'u',
                'u',
                'u',
                'u',
                'y',
                'y'
            );
        }
        $string = preg_replace($search, $replace, $string);
        $string = preg_replace('/[[:space:]]+/', '-', $string);
        // the first below '-' char is (hex)2D, not (hex)20
        $string = preg_replace('/([\!|\$\%|\#|\;|\:|\.|\,|\/|?|-|+|*|~|_]+)/', '-', $string);
        $string = str_replace("'", '', $string);
        $string = str_replace('"', '', $string);

        return $string;
    }

}
