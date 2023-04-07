<?php

namespace Oclockdev\KeycloakJwtGuard\Exception;

use Exception;

class BadPropertyNameException extends Exception{

    protected $code = 500;
    public function __construct(string $property)
    {
        parent::__construct(sprintf("The property %s cannot be set in options.", $property));
    }

}