<?php

class HTTPUtility
{
    public const HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";

    public static function ParseHeaders($raw_headers): array
    {
        $headers = array();
        $key = '';

        foreach (explode("\n", $raw_headers) as $i => $h)
        {
            $h = explode(':', $h, 2);

            if (isset($h[1]))
            {
                if (!isset($headers[$h[0]]))
                    $headers[$h[0]] = trim($h[1]);
                elseif (is_array($headers[$h[0]]))
                    $headers[$h[0]] = array_merge($headers[$h[0]], array(trim($h[1])));
                else
                    $headers[$h[0]] = array_merge(array($headers[$h[0]]), array(trim($h[1])));

                $key = $h[0];
            }
            else
            {
                if (substr($h[0], 0, 1) == "\t")
                    $headers[$key] .= "\r\n\t" . trim($h[0]);
                elseif (!$key)
                    $headers[0] = trim($h[0]);
                trim($h[0]);
            }
        }

        return $headers;
    }

    public static function GetResponseHeader($headers): ?array
    {
        foreach ($headers as $key => $r)
        {
            if (stripos($r, 'HTTP/') === 0)
            {
                $items = explode(' ', $r, 3);
                return array(
                    "code" => $items[1],
                    "status" => $items[2]
                );
            }
        }

        return null;
    }

    public static function ParseAuthenticationString($str): ?array
    {
        $authParameters = array();

        foreach (explode(",", $str) as $i)
        {
            $ii = explode("=", trim($i), 2);
            if (!empty($ii[1]) && !empty($ii[0]))
                $authParameters[$ii[0]] = preg_replace("/^\"/", '', preg_replace("/\"$/", '', $ii[1]));
        }

        return $authParameters;
    }

    public static function BuildAuthenticationString(array $pars)
    {
        $authString = "";

        foreach ($pars as $k => $v)
        {
            if (empty($k) || empty($v)) continue;
            $authString .= $k . '="' . $v . '", ';
        }

        return trim($authString, ", ");
    }

    public static function FindBoundary($headers, $defaultValue)
    {
        if ($headers == null || count($headers) == 0)
            return $defaultValue;

        $fullString = implode("\r\n", $headers);
        $pattern = "/boundary=(\"?)(?<boundary>[A-z0-9]*)(\"?)/";

        $matches = null;

        if (preg_match($pattern, $fullString, $matches))
            return $matches["boundary"];

        return $defaultValue;
    }
}

class WWWAuthenticateHeader
{
    public function __construct($header)
    {
        if (is_array($header))
            foreach ($header as $challenge)
                $this->AddChallenge($challenge);
        else
            $this->AddChallenge($header);
    }

    private function AddChallenge($rawChallenge)
    {
        if (!$this->challenges)
            $this->challenges = array();

        if (strex_startsWith($rawChallenge, "Digest") && !key_exists("Digest", $this->challenges))
            $this->challenges["Digest"] = new DigestAuthChallenge(trim(substr($rawChallenge, 6)));
        else if (strex_startsWith($rawChallenge, "Basic") && !key_exists("Basic", $this->challenges))
            $this->challenges["Basic"] = new BasicAuthChallenge(trim(substr($rawChallenge, 5)));
    }

    private $challenges;

    public function GetChallenges(): ?array
    {
        return $this->challenges;
    }

    public function FindBasicChallenge(): ?BasicAuthChallenge
    {
        if ($this->challenges["Basic"])
            return $this->challenges["Basic"];

        return null;
    }

    public function FindDigestChallenge(): ?DigestAuthChallenge
    {
        if ($this->challenges["Digest"])
            return $this->challenges["Digest"];

        return null;
    }
}

class BasicAuthChallenge
{
    public function __construct($rawChallenge)
    {
        $parameters = HTTPUtility::ParseAuthenticationString($rawChallenge);

        $this->realm = $parameters["realm"];
    }

    public $realm;

    public function DoChallenge($username, $password)
    {
        return "Basic " . base64_encode($username . ":" . $password);
    }
}

class DigestAuthChallenge
{
    public function __construct($rawChallenge)
    {
        $parameters = HTTPUtility::ParseAuthenticationString($rawChallenge);

        $this->realm = $parameters["realm"];
        $this->nonce = $parameters["nonce"];
        $this->qop = $parameters["qop"];
        $this->cnonce = substr(md5(rand()), 0, 8);
        $this->nc = "1";
    }

    public $realm;
    public $nonce;
    public $qop;
    public $nc;
    public $cnonce;

    public function BuildHA1($username, $password)
    {
        return md5($username . ":" . $this->realm . ":" . $password);
    }

    public function BuildHA2($method, $uri)
    {
        return md5($method . ":" . $uri);
    }

    public function BuildResponse($username, $password, $method, $uri)
    {
        return md5($this->BuildHA1($username, $password) . ":" . $this->nonce . ":" . $this->nc . ":" . $this->cnonce . ":" . $this->qop . ":" . $this->BuildHA2($method, $uri));
    }

    public function BuildChallenge($username, $password, $method, $uri)
    {
        return array(
            "username" => $username,
            "realm" => $this->realm,
            "nonce" => $this->nonce,
            "uri" => $uri,
            "qop" => $this->qop,
            "nc" => $this->nc,
            "cnonce" => $this->cnonce,
            "response" => $this->BuildResponse($username, $password, $method, $uri)
        );
    }

    public function DoChallenge($username, $password, $method, $uri)
    {
        return "Digest " . HTTPUtility::BuildAuthenticationString($this->BuildChallenge($username, $password, $method, $uri));
    }
}