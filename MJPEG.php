<?php

class MJPEGStream
{
    function __construct($host, $mjpegPath, $useSSL = true, $verifySSL = true, $allowSelfSigned = false, $connectionErrorCallback = null, $frameReceivedCallback = null)
    {
        $this->host = $host;
        $this->mjpegPath = $mjpegPath;
        $this->useSSL = $useSSL;
        $this->verifySSL = $verifySSL;
        $this->allowSelfSigned = $allowSelfSigned;
        $this->connectionErrorCallback = $connectionErrorCallback;
        $this->frameReceivedCallback = $frameReceivedCallback;
    }

    public const AUTH_NONE = "none";
    public const AUTH_AUTO = "auto";
    public const AUTH_BASIC = "basic";
    public const AUTH_DIGEST = "digest";

    public const DEFAULT_MAX_EXECUTION_TIME = 600;
    public const DEFAULT_TIMEOUT = 30;
    public const DEFAULT_BOUNDARY = "myboundary";

    public $host = "";
    public $mjpegPath = "";
    public $useSSL = true;
    public $verifySSL = false;
    public $allowSelfSigned = false;
    public $defaultBoundary = MJPEGStream::DEFAULT_BOUNDARY;
    public $timeout = MJPEGStream::DEFAULT_TIMEOUT;
    public $maxExecutionTime = MJPEGStream::DEFAULT_MAX_EXECUTION_TIME;

    public function SetCredentails($username, $password, $auth = MJPEGStream::AUTH_AUTO)
    {
        $this->username = $username;
        $this->password = $password;
        $this->authentication = $auth;
    }

    public $authentication = MJPEGStream::AUTH_NONE;
    public $username = "";
    public $password = "";

    public $mjpegHandler;

    private $streamActive = false;
    private $streamSocket = null;

    public function IsActive(): bool
    {
        return $this->streamActive;
    }

    public function Start()
    {
        if ($this->streamActive)
            return;

        $this->streamActive = true;

        $this->__startStream();
    }

    public function Stop()
    {
        $this->streamActive = false;
        $this->__stopStream();
    }

    private function __initStream(&$errno, &$errstr): bool
    {
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => $this->verifySSL,
                'verify_peer_name' => $this->verifySSL,
                'allow_self_signed' => $this->allowSelfSigned
            ]
        ]);

        $this->streamSocket = null;

        $socket = stream_socket_client(($this->useSSL ? "ssl" : "tcp") . "://$this->host", $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $context);

        if ($socket == false)
            return false;

        $this->streamSocket = $socket;

        return true;
    }

    private function __startStream()
    {
        if (!$this->__initStream($errCode, $errMsg))
        {
            $this->__connectionError($errCode, $errMsg, false);
            return;
        }

        $time = time();

        $customHeaders = array();
        $useAutoAuth = false;

        switch ($this->authentication)
        {
            case MJPEGStream::AUTH_BASIC:
                $customHeaders[] = "Authorization: Basic " . base64_encode($this->username . ":" . $this->password);
                break;
            case MJPEGStream::AUTH_DIGEST:
            case MJPEGStream::AUTH_AUTO:
                $useAutoAuth = true;
                $customHeaders[] = "Connection: close";
                break;
        }

        $this->__sendRequestHeaders($customHeaders);

        $response = $this->__readResponse();

        $responseHeaders = HTTPUtility::ParseHeaders(implode("\r\n", $response));
        $responseHeader = HTTPUtility::GetResponseHeader($responseHeaders);

        //Check for success
        if ($responseHeader)
        {
            if ($responseHeader["code"] == 401 && $useAutoAuth)
            {
                $wwwAuthenticateHeader = $responseHeaders[HTTPUtility::HEADER_WWW_AUTHENTICATE];
                $authChallenges = new WWWAuthenticateHeader($wwwAuthenticateHeader);

                $customRetryHeaders = array();

                if ($digestChallenge = $authChallenges->FindDigestChallenge())
                    $customRetryHeaders[] = "Authorization: " . $digestChallenge->DoChallenge($this->username, $this->password, "GET", $this->mjpegPath);
                else if ($this->authentication != MJPEGStream::AUTH_DIGEST && ($basicChallenge = $authChallenges->FindBasicChallenge()))
                    $customRetryHeaders[] = "Authorization: " . $basicChallenge->DoChallenge($this->username, $this->password);
                else
                    $customRetryHeaders = null;

                if ($customRetryHeaders)
                {
                    if (!$this->__initStream($errCode, $errMsg))
                    {
                        $this->__connectionError($errCode, $errMsg, false);
                        return;
                    }

                    $this->__sendRequestHeaders($customRetryHeaders);

                    $response = $this->__readResponse();

                    $responseHeaders = HTTPUtility::ParseHeaders(implode("\r\n", $response));
                    $responseHeader = HTTPUtility::GetResponseHeader($responseHeaders);
                }
            }

            if ($responseHeader["code"] != 200)
            {
                $this->__connectionError($responseHeader["code"], $responseHeader["status"], true);
                return;
            }
        }
        else
        {
            $this->__connectionError(600, "HTTP Error", true);
            return;
        }

        foreach ($responseHeaders as $hk => $hv)
        {
            $header = "$hk: $hv";

            $mjpegStreamHeaders[] = $header;

            $this->__connectionHeaderArrived($header);
        }

        $frameId = 0;

        // Find the Boundary
        $boundary = HTTPUtility::FindBoundary($responseHeaders, $this->defaultBoundary);

        // Stop the script after the max execution time automatically
        set_time_limit($this->maxExecutionTime);

        while (!connection_aborted() && $this->streamActive)
        {
            $frameId++;
            $currentFrame = "";

            // Wait for a full frame
            while (substr_count($currentFrame, "\xFF\xD8") < 2)
            {
                $currentPart = "";
                $currentPart .= (fgets($this->streamSocket));
                $currentFrame .= $currentPart;

                $this->__framePartArrived($boundary, $frameId, $currentPart);
            }

            $this->__frameArrived($boundary, $frameId, $currentFrame);
        }

        $this->__stopStream();
    }

    private function __sendRequestHeaders(?array $customHeaders = null)
    {
        $headers = array(
            "GET $this->mjpegPath HTTP/1.0",
            "Host: $this->host"
        );

        if ($customHeaders)
            $headers = array_merge($headers, $customHeaders);

        fputs($this->streamSocket, implode("\r\n", $headers) . "\r\n\r\n");
    }

    private function __readResponse()
    {
        $response = array();

        while ($str = trim(fgets($this->streamSocket, 4096)))
            $response[] = $str;

        return $response;
    }

    private function __stopStream()
    {
        fclose($this->streamSocket);
        $this->streamSocket = null;
    }

    private function __connectionError($errCode, $errMsg, $isHttpError)
    {
        $this->streamActive = false;
        $this->__stopStream();

        if ($this->mjpegHandler)
            $this->mjpegHandler->OnConnectionError($errCode, $errMsg, $isHttpError);
    }

    private function __connectionHeaderArrived($header)
    {
        if ($this->mjpegHandler)
            $this->mjpegHandler->OnHeaderArrived($header);
    }

    private function __framePartArrived($boundary, $frameId, $framePart)
    {
        if ($this->mjpegHandler)
            $this->mjpegHandler->OnFramePartArrived($boundary, $frameId, $framePart);
    }

    private function __frameArrived($boundary, $frameId, $frame)
    {
        if ($this->mjpegHandler)
            $this->mjpegHandler->OnFrameArrived($boundary, $frameId, $frame);
    }
}