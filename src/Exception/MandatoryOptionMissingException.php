<?php

namespace Oclockdev\KeycloakJwtGuard\Exception;

use Exception;

class MandatoryOptionMissingException extends Exception{

    protected $code = 500;
    public function __construct(string $option)
    {
        parent::__construct(sprintf("The %s option is required.", $option));
    }

}