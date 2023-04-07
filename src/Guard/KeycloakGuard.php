<?php


namespace Oclockdev\KeycloakJwtGuard\Guard;


use Oclockdev\KeycloakJwtGuard\Exception\BadPropertyNameException;
use Oclockdev\KeycloakJwtGuard\Exception\MandatoryOptionMissingException;
use Oclockdev\KeycloakJwtGuard\Exception\MissingTokenException;
use Oclockdev\KeycloakJwtGuard\Utils\Bearer;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use stdClass;

class KeycloakGuard{

    protected ?string $serverUrl;

    protected ?string $realm;

    protected ?string $accessToken = null;

    protected ?stdClass $payload = null;

    const MANDATORIES = [
        'serverUrl',
        'realm',
    ];

    private Client $httpClient;

    public function __construct( array $options )
    {
        $this->fillProperties($options);
        $this->httpClient = new Client();
    }


    /**
     * Fill the property from option list
     * @throws BadPropertyNameException|MandatoryOptionMissingException
     */
    private function fillProperties(array $options ): void
    {

        foreach ( $options as $property => $value ){
            if( property_exists( $this, $property ) ){
                $this->$property = $value;
            }else{
                throw new BadPropertyNameException( $property );
            }
        }

        $this->verifyMandatories();

    }

    /**
     * Verify if mandatory properties are provided in options
     * @return void
     * @throws MandatoryOptionMissingException
     */
    private function verifyMandatories(): void
    {
        foreach ( self::MANDATORIES as $property ){
            if( !isset($this->$property) || $this->$property === null ){
                throw new MandatoryOptionMissingException($property);
            }
        }
    }

    /**
     * Return the Jwks url
     * @return string
     */
    private function getCertsUrl(): string
    {
        return $this->getRealmUrl()."/protocol/openid-connect/certs";
    }

    /**
     * Return the keycloak base url with realm
     * @return string
     */
    private function getRealmUrl():string
    {
        return $this->serverUrl.'/realms/'.$this->realm;
    }

    private function getUserinfoUrl():string
    {
        return $this->serverUrl.'/realms/'.$this->realm."/protocol/openid-connect/userinfo";
    }

    /**
     * @param string|null $bearerToken
     * @return stdClass
     * @throws GuzzleException
     * @throws MissingTokenException
     */
    public function authenticate( ?string $bearerToken = null  ): stdClass
    {
        if( $bearerToken === null ){
            $bearerToken = $this->accessToken;
        }

        if( $this->accessToken === null ){
            throw new MissingTokenException();
        }

        $this->accessToken = Bearer::extractAccessToken($bearerToken);
        // Get the JWKS for decoding token
        $certs = $this->requestForJson( $this->getCertsUrl());
        $this->payload = JWT::decode( $this->accessToken, JWK::parseKeySet($certs));
        return $this->payload;
    }

    /**
     * @param string $accessToken
     * @return KeycloakGuard
     */
    public function setAccessToken( string $accessToken ): self
    {
        $this->accessToken = Bearer::extractAccessToken($accessToken);
        return $this;
    }

    /**
     * Return json decoded response for a request
     *
     * @param string $url
     * @param string $method
     * @param array $options
     * @param bool $associative
     * @return array|stdClass|null
     * @throws GuzzleException
     */
    private function requestForJson(  string $url, string $method = "GET", array $options = [], $associative = true): array|stdClass|null
    {

        $response = $this->httpClient->request(
            $method,
            $url,
            $options
        );
        return json_decode($response->getBody()->getContents(), $associative);
    }

    /**
     *  Send a request to userinfo keycloak endpoint with access token in order
     *
     * @param string|null $bearerToken
     * @return array|null
     * @throws GuzzleException
     * @throws MissingTokenException
     */
    public function getOwnerRessource( ?string $bearerToken = null ): ?array
    {
        if( $bearerToken === null ){
            $bearerToken = $this->accessToken;
        }

        if( $this->accessToken === null ){
            throw new MissingTokenException();
        }

        return $this->requestForJson( $this->getUserinfoUrl(), "GET", [
            "headers" => Bearer::getHeaderAuthorization( $this->accessToken )
        ]);
    }

    /**
     * @return string|null
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }


}