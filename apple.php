<?php
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Parser;
use Request; //* use curl function to request

class Apple extends CI_controller
{
    public function __construct()
    {
        parent::__construct();
        $this->request = new Request;
    }

    public function phase_token()
    {
        $param = $this->input->post(NULL, TRUE);

        $token = (new Parser())->parse((string) $param['id_token']); // Parses from a string
        $email = $token->getClaim('email');
        $header_key = array('alg', 'kid');
        $claim_key  = array('iss', 'aud', 'exp', 'iat', 'sub', 'c_hash', 'email', 'email_verified', 'auth_time', 'nonce_supported');
        $return = array(
            'header' => array(),
            'claim' => array(),
        );

        foreach ($header_key as $key)
        {
            $return['header'][$key] = $token->getHeader($key);
        }

        foreach ($claim_key as $key)
        {
            $return['claim'][$key] = $token->getClaim($key);
        }

        //*use of auth token if you need
        // $auth =  $this->auth_token($param['code']);
        // if ($auth == FALSE)
        // {
        //     return FALSE;
        // }
        // echo json_encode($auth);return;

        //*use of refreshing token if you need
        // $refresh = $this->auth_token($auth['refresh_token'], 'refresh_token');
        // if ($auth == FALSE)
        // {
        //     return FALSE;
        // }
        // echo json_encode($refresh);return;

        
        //sub is apple id
        //
        echo base64_encode($this->aes->encrypt(json_encode($return)));
    }

    public function auth_token($data, $type = 'authorization_code')
    {
        $param = array();
        $param['client_id']     = 'your app uid';
        $param['client_secret'] = $this->_get_secret_key();

        $param['redirect_uri']  = '{redirect uri setting in apple}';
        if ($type == 'authorization_code')
        {
            $param['code']           = $data;
        }
        else if ($type == 'refresh_token')
        {
            $param['refresh_token']  = $data;
        }
        else
        {
            return FALSE;
        }
        $param['grant_type']     = $type;

        $response = $this->request->send_request('POST', 'https://appleid.apple.com/auth/token', $param);
        if ($response['info']['http_code'] != 200)
        {
            return FALSE;
        }

        return json_decode($response['result'], TRUE);
    }

    private function _get_secret_key()
    {
        //* you can use this to check php get your p8 file
        // echo dirname(dirname(__FILE__));
        // echo '<br>';
        // var_dump(file_exists(dirname(dirname(__FILE__)) . '/config/Auth_key_yourkid.p8'));
        // return;
        $signer = new Sha256();
        $privateKey = new Key('file://' .  '{your secret key p8 file path}');
        date_default_timezone_set('UTC'); //* time zone assigned
        $time = time();

        $token = (new Builder())->withHeader('alg', 'ES256')
                                ->withHeader('kid', 'your key id in p8 file')  //*inter your secret key id getting from apple credential account 
                                ->permittedFor('https://appleid.apple.com') //* fixed value
                                ->issuedAt($time) //* issued time in UTC
                                ->expiresAt($time + 3600) //* expired time in UTC
                                ->withClaim('iss', 'your Team ID')//* iss: Team ID
                                ->withClaim('sub', 'your app uid') 
                                ->getToken($signer,  $privateKey); // Retrieves the generated token
        date_default_timezone_set('Asia/Taipei'); 
        return (string) $token;
    }
}
