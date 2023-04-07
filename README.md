# keycloak-jwt-guard
A library to decode JWT provided by Keycloak 


## How to use?

```php

<?php

use Oclockdev\KeycloakJwtGuard\Guard\KeycloakGuard;

require_once "./vendor/autoload.php";


// Get the bearer token from the request
$accessToken = $_SERVER['HTTP_AUTHORIZATION'];

// Create a new instance of KeycloakGuard with Keycloak server info
$keycloakGuard = new KeycloakGuard([
    "serverUrl" => "https://localhost:8080",
    "realm"     => "master",
    "accessToken" => $accessToken
]);

// Authenticate with the access token and return the JWT payload
$payload = $keycloakGuard->authenticate();

// Call the userinfo keycloak endpoint with the access token
$userinfo = $keycloakGuard->getOwnerRessource();


```