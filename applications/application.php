<?php
/**
 * Generate A Response text
 */
function _generate_response_message(
    $message,
    int $status = 0,
    string $description = ""
):String{
    return json_encode(array(
        'status'=>$status,
        'message'=>$message,
        'description'=>$description
    ), JSON_UNESCAPED_UNICODE);
}

/**
 * Return a number is odd
 */
function _is_odd(int $n):bool{
    return $n % 2 == 1 || $n % 2 == -1;
}

/**
 * XSS Check
 */
function _xss_check(string $s):bool{
    $xss_texts = ['<', '>', '"', '\'' ,'/'];
    for ($i = 0; $i < count($xss_texts); $i++){
        if (strstr($s, $xss_texts[$i])){
            return false;
        }
    }
    return true;
}

/**
 * Get real ip
 * A tip: if you are using Cloudflare, please change the default value of $isUsingCloudflare to true
 * If one of your services are not using cloudflare, don't change it,
 * because the attacker know it, too.
 */
function _get_real_ip(bool $isUsingCloudflare = false):string{
    if (!empty($_SERVER["HTTP_CF_CONNECTING_IP"]) && $isUsingCloudflare === true){
        $ipaddress = $_SERVER["HTTP_CF_CONNECTING_IP"];
    }elseif (!empty($_SERVER["HTTP_X_FORWARDED_FOR"])){
        $ip_list = explode(",", $_SERVER['HTTP_X_FORWARDED_FOR']);
        foreach ($ip_list as $ip){
            $ip = trim($ip);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)){
                $ipaddress = $ip;
                break;
            }
        }
    }
    if (empty($ipaddress)){
        $ipaddress = $_SERVER["REMOTE_ADDR"];
    }
    return $ipaddress;
}

/**
 * SQL Check
 */
function _sql_check(string $s):bool{
    $sql_texts = array(' ', '\'', '\"', 'INSERT', 'UPDATE', 'DELETE', 'SELECT', "OR", "AND", "UNION", '\' OR \'', '\" OR \"');
    $s = strtoupper($s);
    for ($i = 0; $i < count($sql_texts); $i++){
        if (strstr($s, $sql_texts[$i])){
            return false;
        }
    }
    return true;
}

/**
 * Password encode
 */
function _encode_password($password, $salt){
    return md5(md5($password).$salt); // == Discuz!
}