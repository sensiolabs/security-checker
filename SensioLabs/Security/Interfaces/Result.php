<?php

namespace SensioLabs\Security\Interfaces;

/**
 * Any class that implements this interface will be able to be used in the SecurityChecker
 *
 * Interface Result
 * @package SensioLabs\Security\Interfaces
 */
interface Result extends \Countable {
    /**
     * Fills in the data
     *
     * @param int $count
     * @param string $vulnerabilities
     * @param string $format
     * @return self
     */
    public function fill($count, $vulnerabilities, $format);

    /**
     * Which format was passed on or does this class use
     *
     * If set manually, choose one of:
     *   text
     *   simple
     *   markdown
     *   yaml
     *   json
     *   ansi
     *
     * @see \SensioLabs\Security\Crawler::getContentType
     *
     *
     * @return string
     */
    public function getFormat();

    /**
     * How many security vulnerabilities were found
     *
     * @return int
     */
    public function count();

    /**
     * What to print when casting this object to a string
     *
     * @return string
     */
    public function __toString();
}
