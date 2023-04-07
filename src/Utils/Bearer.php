<?php

namespace Oclockdev\KeycloakJwtGuard\Utils;

class Bearer{

    /**
     * @param string $bearerToken
     * @return string
     */
    public static function extractAccessToken( string $bearerToken ): string
    {
        return str_replace("Bearer ", "", $bearerToken);
    }

    /**
     * Return the header authorization token
     * @param string $accessToken
     * @return string[]
     */
    public static function getHeaderAuthorization( string $accessToken ): array
    {
        if( !str_contains( $accessToken, "Bearer " ) ){
            $accessToken = "Bearer ".$accessToken;
        }

        return [
            "Authorization" => $accessToken
        ];
    }
}