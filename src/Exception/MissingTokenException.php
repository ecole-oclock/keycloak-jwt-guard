<?php

namespace Oclockdev\KeycloakJwtGuard\Exception;

use Exception;

class MissingTokenException extends Exception{

    protected $code = 500;
    public function __construct()
    {
        parent::__construct("AccessToken hasn't been provided.");
    }

}