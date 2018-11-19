<?php

namespace SensioLabs\Security\Interfaces;

/**
 * Any class that implements this interface will be able to be used in the SecurityChecker
 *
 * Interface Result
 * @package SensioLabs\Security\Interfaces
 */
interface Result {
    /**
     * Fills in the data
     *
     * @param $count
     * @param $vulnerabilities
     * @param $format
     * @return mixed
     */
    public function fill($count, $vulnerabilities, $format);

    /**
     * Which format was passed on
     *
     * @return mixed
     */
    public function getFormat();

    /**
     * How many security vulnerabilities were found
     *
     * @return mixed
     */
    public function count();
}
