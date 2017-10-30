<?php

/**
 * Single sign-on server.
 *
 * The SSO server is responsible of managing users sessions which are available for brokers.
 *
 * Normally you'd fetch the broker info and user info from a database, rather then declaring them in the code.
 * This class may be used as controller in an MVC application.
 */

if (!function_exists('getallheaders')) {
    function getallheaders() {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }
}

class SSOServer
{
    /**
     * Registered brokers
     * @var array
     */
    private static $brokers = [
        'Betelgeuse' => ['secret' => 'd6cfca165058a7d43f85d5bb5ffcbe45'],
        'Vega' => ['secret' => '64d8c5e0e73635dc894032f156884f23'],
        'Deneb' => ['secret' => '5df4fa19a5d1983fb59861d15f40b99a']
    ];

    /**
     * System users
     * @var array
     */
    private static $users = [
        'jack' => [
            'fullname' => 'Jack Sparrow',
            'email' => 'captain.jack@blackpearl.com',
            'password' => '$2y$10$B8Hc0mzCQVu4VbCC6KulKuNcJd6l62Ls48BnTSPYt15aL3ScFjshO' // jack123
        ],
        'han' => [
            'fullname' => 'Han Solo',
            'email' => 'rebel.scum@falcon.com',
            'password' => '$2y$10$c5UMR6kKzA9rTNeEZnLkQergIW4Md5GpYLKrC5pJSmsdwu1xoq.Nm' // han123
        ]
    ];

    /**
     * @var array
     */
    //protected $options = ['files_cache_directory' => '/tmp', 'files_cache_ttl' => 36000];

    /**
     * Cache that stores the special session data for the brokers.
     *
     * @var Cache
     */
    //protected $cache;

    protected $returnType;

    protected $brokerId;

    protected $cacheFile = '/tmp';

    /**
     * Class constructor
     *
     * @param array $options
     */
    public function __construct()
    {

    }

    /**
     * Create a cache to store the broker session id
     *
     *  == TODO: move this to Redis ==
     */
    protected function setCache($key, $sessionId)
    {
        // $this->cache->set($sid, $this->getSessionData('id'));

        $item = serialize(
            [
                'value' => $sessionId,
                'ttl' => 999999
            ]
        );

        error_log('***** SET PATH *****');
        error_log($this->getFilename($key));

        if (!file_put_contents($this->getFilename($key), $item)) {
            throw new \Exception(sprintf('Error saving data with the key "%s" to the cache file.', $key));
        }
    }

    /**
     * Read from cache
     *
     * @return string   session id
     */
    protected function getCache($key)
    {
        $path = $this->getFilename($key);

        if (!file_exists($path)) {
            return;
        }

        $rawData = file_get_contents($path);
        $data = unserialize($rawData);
        if (!$data) {
            return;
        }

        return $data['value'];
    }

    protected function getFilename($key)
    {
        return $this->cacheFile . '/' . $key;
    }

    /**
     * Start the session for broker requests to the SSO server
     */
    public function startBrokerSession()
    {
        if (isset($this->brokerId)) return;

        $sid = $this->getBrokerSessionID();

        if ($sid === false) {
            return $this->fail("Broker didn't send a session key", 400);
        }

        $linkedId = $this->getCache($sid);

        if (!$linkedId) {
            return $this->fail("The broker session id isn't attached to a user session", 403);
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            if ($linkedId !== session_id()) throw new \Exception("Session has already started", 400);
            return;
        }

        session_id($linkedId);
        session_start();

        $this->brokerId = $this->validateBrokerSessionId($sid);
    }

    /**
     * Get session ID from header Authorization or from $_GET/$_POST
     */
    protected function getBrokerSessionID()
        {
            $headers = getallheaders();

            if (isset($headers['Authorization']) && strpos($headers['Authorization'], 'Bearer') === 0) {
                $headers['Authorization'] = substr($headers['Authorization'], 7);
                return $headers['Authorization'];
            }
            if (isset($_GET['access_token'])) {
                return $_GET['access_token'];
            }
            if (isset($_POST['access_token'])) {
                return $_POST['access_token'];
            }
            if (isset($_GET['sso_session'])) {
                return $_GET['sso_session'];
            }

            return false;
        }

    /**
     * Validate the broker session id
     *
     * @param string $sid session id
     * @return string  the broker id
     */
    protected function validateBrokerSessionId($sid)
    {
        $matches = null;

        if (!preg_match('/^SSO-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $this->getBrokerSessionID(), $matches)) {
            return $this->fail("Invalid session id");
        }

        $brokerId = $matches[1];
        $token = $matches[2];

        if ($this->generateSessionId($brokerId, $token) != $sid) {
            return $this->fail("Checksum failed: Client IP address may have changed", 403);
        }

        return $brokerId;
    }

    /**
     * Start the session when a user visits the SSO server
     */
    protected function startUserSession()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateSessionId($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (!isset($broker)) return null;

        return "SSO-{$brokerId}-{$token}-" . hash('sha256', 'session' . $token . $broker['secret']);
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @return string
     */
    protected function generateAttachChecksum($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);

        if (!isset($broker)) return null;

        return hash('sha256', 'attach' . $token . $broker['secret']);
    }


    /**
     * Detect the type for the HTTP response.
     * Should only be done for an `attach` request.
     */
    protected function detectReturnType()
    {
        if (!empty($_GET['return_url'])) {
            $this->returnType = 'redirect';
        } elseif (!empty($_GET['callback'])) {
            $this->returnType = 'jsonp';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'image/') !== false) {
            $this->returnType = 'image';
        } elseif (strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            $this->returnType = 'json';
        }
    }

    /**
     * Attach a user session to a broker session
     */
    public function attach()
    {
        $this->detectReturnType();

        if (empty($_REQUEST['broker'])) return $this->fail("No broker specified", 400);
        if (empty($_REQUEST['token'])) return $this->fail("No token specified", 400);

        if (!$this->returnType) return $this->fail("No return url specified", 400);

        $checksum = $this->generateAttachChecksum($_REQUEST['broker'], $_REQUEST['token']);

        if (empty($_REQUEST['checksum']) || $checksum != $_REQUEST['checksum']) {
            return $this->fail("Invalid checksum", 400);
        }

        $this->startUserSession();
        $sid = $this->generateSessionId($_REQUEST['broker'], $_REQUEST['token']);

        $this->setCache($sid, $this->getSessionData('id'));
        $this->outputAttachSuccess();
    }

    /**
     * Output on a successful attach
     */
    protected function outputAttachSuccess()
    {
        if ($this->returnType === 'image') {
            $this->outputImage();
        }

        if ($this->returnType === 'json') {
            header('Content-type: application/json; charset=UTF-8');
            echo json_encode(['success' => 'attached']);
        }

        if ($this->returnType === 'jsonp') {
            $data = json_encode(['success' => 'attached']);
            echo $_REQUEST['callback'] . "($data, 200);";
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'];
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
        }
    }

    /**
     * Output a 1x1px transparent image
     */
    protected function outputImage()
    {
        header('Content-Type: image/png');
        echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQ'
            . 'MAAAAl21bKAAAAA1BMVEUAAACnej3aAAAAAXRSTlMAQObYZg'
            . 'AAAApJREFUCNdjYAAAAAIAAeIhvDMAAAAASUVORK5CYII=');
    }

    /**
     * Authenticate
     */
    public function login()
    {
        $this->startBrokerSession();

        if (empty($_POST['username'])) $this->fail("No username specified", 400);
        if (empty($_POST['password'])) $this->fail("No password specified", 400);

        $validation = $this->authenticate($_POST['username'], $_POST['password']);

        if (!$validation[0]) {
            return $this->fail($validation[1], 400);
        }

        $this->setSessionData('sso_user', $_POST['username']);
        $this->userInfo();
    }

    /**
     * Log out
     */
    public function logout()
    {
        $this->startBrokerSession();
        $this->setSessionData('sso_user', null);

        header('Content-type: application/json; charset=UTF-8');
        http_response_code(204);
    }

    /**
     * Ouput user information as json.
     */
    public function userInfo()
    {
        $this->startBrokerSession();
        $user = null;

        $username = $this->getSessionData('sso_user');

        if ($username) {
            $user = $this->getUserInfo($username);
            error_log('BrokerSessionId: '.$this->getBrokerSessionID());
            $user['sessionId'] = $this->getCache($this->getBrokerSessionID());
            if (!$user) return $this->fail("User not found", 500); // Shouldn't happen
        }

        header('Content-type: application/json; charset=UTF-8');
        echo json_encode($user);
    }

    /**
     * Set session data
     *
     * @param string $key
     * @param string $value
     */
    protected function setSessionData($key, $value)
    {
        if (!isset($value)) {
            unset($_SESSION[$key]);
            return;
        }

        $_SESSION[$key] = $value;
    }

    /**
     * Get session data
     *
     * @param type $key
     */
    protected function getSessionData($key)
    {
        if ($key === 'id') return session_id();

        return isset($_SESSION[$key]) ? $_SESSION[$key] : null;
    }

    /**
     * An error occured.
     *
     * @param string $message
     * @param int    $http_status
     */
    protected function fail($message, $http_status = 500)
    {
        if (!empty($this->options['fail_exception'])) {
            throw new \Exception($message, $http_status);
        }

        if ($http_status === 500) trigger_error($message, E_USER_WARNING);

        if ($this->returnType === 'jsonp') {
            echo $_REQUEST['callback'] . "(" . json_encode(['error' => $message]) . ", $http_status);";
            exit();
        }

        if ($this->returnType === 'redirect') {
            $url = $_REQUEST['return_url'] . '?sso_error=' . $message;
            header("Location: $url", true, 307);
            echo "You're being redirected to <a href='{$url}'>$url</a>";
            exit();
        }

        http_response_code($http_status);
        header('Content-type: application/json; charset=UTF-8');

        echo json_encode(['error' => $message]);
        exit();
    }


    /**
     * Get the API secret of a broker and other info
     *
     * @param string $brokerId
     * @return array
     */
    protected function getBrokerInfo($brokerId)
    {
        return isset(self::$brokers[$brokerId]) ? self::$brokers[$brokerId] : null;
    }

    /**
     * Authenticate using user credentials
     *
     * @param string $username
     * @param string $password
     * @return array
     */
    protected function authenticate($username, $password)
    {
        if (!isset($username)) {
            return [false, "username isn't set"];
        }

        if (!isset($password)) {
            return [false, "password isn't set"];
        }

        if (!isset(self::$users[$username]) || !password_verify($password, self::$users[$username]['password'])) {
            return [false, "Invalid credentials"];
        }

        return [true, ''];
    }


    /**
     * Get the user information
     *
     * @return array
     */
    protected function getUserInfo($username)
    {
        if (!isset(self::$users[$username])) return null;

        $user = compact('username') + self::$users[$username];
        unset($user['password']);

        return $user;
    }
}

