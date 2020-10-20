<?php
require_once 'bytebuffer/Cast.php';
require_once 'bytebuffer/BufferException.php';
require_once 'bytebuffer/Buffer.php';
require_once 'bytebuffer/ResourceBuffer.php';
require_once 'bytebuffer/MemoryResourceBuffer.php';

class DDNS{
    
    /** 
     * Debug buffer
     * @var string
     */
    private $debugBuffer;
    
    public function __constructor(){}
    
    public function init(){
        $this->debug("REQUEST: ".json_encode($_SERVER));
        $this->debug("SERVER: ".json_encode($_REQUEST));
        
        $this->checkHttpMethod();
        $auth = $this->checkAuthentication();
        
        if(!isset($_REQUEST['hostname'])){
            $this->debug('ERROR: no hostname');
            $this->returnCode('badrequest', array('HTTP/1.0 400 Bad Request'));
        }
            
        $hostname = $_REQUEST['hostname'];
        $ipv4 = (isset($_REQUEST['ipv4']) && empty(!$_REQUEST['ipv4']) ? $_REQUEST['ipv4'] : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ""));
        $ipv6 = (isset($_REQUEST['ipv6']) ? $_REQUEST['ipv6'] : "");
        
        if(empty($ipv4) && empty($ipv6)){
            $this->debug('ERROR: no ipv4 or ipv6');
            $this->returnCode('badrequest', array('HTTP/1.0 400 Bad Request'));
        }
        
        $this->debug("Hostname: ".$hostname);
        $this->debug("ipv4: ".$ipv4);
        $this->debug("ipv6: ".$ipv6);

        $this->send_data($auth[0],$auth[1],$hostname,$ipv4,$ipv6);
        $this->returnCode('good');
    }
    
    private function checkHttpMethod(){
        // Only HTTP method "GET" is allowed here
        if ($_SERVER['REQUEST_METHOD'] != 'GET') {
            $this->debug('ERROR: HTTP method ' . $_SERVER['REQUEST_METHOD'] . ' is not allowed.');
            $this->returnCode('badagent', array('HTTP/1.0 405 Method Not Allowed'));
        }
    }
    
    private function checkAuthentication(){
        // Request user/pw if not submitted yet
        if (!isset($_SERVER['PHP_AUTH_USER'])) {
            $this->debug('No authentication data sent');
            $this->returnCode('badauth', array(
                'WWW-Authenticate: Basic realm="DynDNS API Access"',
                'HTTP/1.0 401 Unauthorized')
                );
        }
        
        $user = strtolower($_SERVER['PHP_AUTH_USER']);
        $password = $_SERVER['PHP_AUTH_PW'];
        $this->debug("user: ".$user);
        $this->debug("password: ".$password);
        
        $mysqli = mysqli_connect("localhost", "root", "", "ddns");
        
        if (!$mysqli) {
            $this->debug("Error: mysql connection failed." . PHP_EOL);
            $this->debug("Debug-Errorcode: " . mysqli_connect_errno() . PHP_EOL);
            $this->debug("Debug-Error: " . mysqli_connect_error() . PHP_EOL);
            $this->shutdown();
        }
        $mysqli->query("CREATE TABLE IF NOT EXISTS `ddns_auth` (`user` varchar(50) NOT NULL,`password` varchar(50) DEFAULT NULL,PRIMARY KEY (`user`)) ENGINE=InnoDB DEFAULT CHARSET=latin1;");
        
        $query = sprintf("SELECT password FROM ddns_auth WHERE user='%s';", $user);
        if ($result = $mysqli->query($query)) {
            if($result->num_rows == 1){
                $row = mysqli_fetch_row($result);
                $result->close();
                
                $this->debug($password . " == " . $row[0]);
                
                if(strcmp($password, $row[0]) != 0){
                    $this->debug("password is wrong... ".$password." ".$row[0]);
                    $this->returnCode('badauth', array('HTTP/1.0 403 Forbidden'));
                }
            }else{
                $this->debug("User not found ".$user);
                $this->returnCode('badauth', array('HTTP/1.0 403 Forbidden'));
            }
        }
        mysqli_close($mysqli);
        
        return array($user,$password);
    }
    
    private function send_data($user, $password, $hostname, $ipv4, $ipv6){
        $server = "localhost";
        $port = 4444;
        
        if(!($sock = socket_create(AF_INET, SOCK_DGRAM, 0)))
        {
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);
            
            $this->debug("Couldn't create socket: [$errorcode] $errormsg");
            $this->returnCode("500 Internal Server Error",array('HTTP/1.0 500 Internal Server Error'));
        }
        
        $buffer = new \Buffer\MemoryResourceBuffer();
        $buffer->insertUTF($user);
        $buffer->insertUTF($password);
        $buffer->insertUTF($hostname);
        $buffer->insertUTF($ipv4);
        $buffer->insertUTF($ipv6);
        
        if( ! socket_sendto($sock, $buffer->toString(), $buffer->size() , 0 , $server , $port))
        {
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);
            
            $this->debug("Could not send data: [$errorcode] $errormsg");
            $this->returnCode("500 Internal Server Error",array('HTTP/1.0 500 Internal Server Error'));
        }
        $this->debug("send Packet to DNS-Server.");
        $buffer->close();
    }
    
    private function returnCode($code, $additionalHeaders = array(), $debugMessage = "")
    {
        foreach ($additionalHeaders as $header) {
            header($header);
        }
        $this->debug('Sending return code: ' . $code);
        echo $code;
        $this->shutdown();
    }
    
    private function shutdown() {
        // Flush debug buffer
        if (($this->debugBuffer != "")) {
            if ($fh = fopen("debug.log", 'a')) {
                fwrite($fh, $this->debugBuffer);
                fclose($fh);
            }
        }
        exit;
    }
    
    public function debug($message){
        $this->debugBuffer .= @date('M j H:i:s') . ' DDNS | ' . $message . "\n";
    }
}
?>