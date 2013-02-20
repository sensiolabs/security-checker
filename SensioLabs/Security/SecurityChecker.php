<?php

namespace SensioLabs\Security;

class SecurityChecker
{
    /**
     * Checks a composer.lock file.
     *
     * @param string $lock   The path to the composer.lock file
     * @param string $format The return format
     *
     * @return mixed The vulnerabilities
     *
     * @throws \InvalidArgumentException When the output format is unsupported
     * @throws \RuntimeException         When the lock file does not exist
     * @throws \RuntimeException         When curl does not work or is unavailable
     */
    public function check($lock, $format = 'text')
    {
        if (!function_exists('curl_init')) {
            throw new \RuntimeException('Curl is required to use this command.');
        }

        if (false === $curl = curl_init()) {
            throw new \RuntimeException('Unable to create a new curl handle.');
        }

        if (is_dir($lock) && file_exists($lock.'/composer.lock')) {
            $lock = $lock.'/composer.lock';
        } elseif (preg_match('/composer\.json$/', $lock)) {
            $lock = str_replace('composer.json', 'composer.lock', $lock);
        }

        if (!is_file($lock)) {
            throw new \RuntimeException('Lock file does not exist.');
        }

        switch ($format) {
            case 'text':
                $accept = 'text/plain';
                break;
            case 'json':
                $accept = 'application/json';
                break;
            default:
                throw new \InvalidArgumentException(sprintf('Unsupported format "%s".', $format));
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_URL, 'https://security.sensiolabs.org/check_lock');
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Accept: '.$accept));
        curl_setopt($curl, CURLOPT_POSTFIELDS, array('lock' => '@'.$lock));
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt($curl, CURLOPT_MAXREDIRS, 3);
        curl_setopt($curl, CURLOPT_FAILONERROR, false);

        $data = curl_exec($curl);

        if (false === $data) {
            $error = curl_error($curl);
            curl_close($curl);

            throw new \RuntimeException(sprintf('An error occurred: %s.', $error));
        }

        $statusCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        if (400 == $statusCode) {
            if ('text' == $format) {
                $error = trim($data);
            } else {
                $data = json_decode($data, true);
                $error = $data['error'];
            }

            throw new \InvalidArgumentException($error);
        }

        if (200 != $statusCode) {
            throw new \RuntimeException('The web service failed for an unknown reason (HTTP '.$statusCode.').');
        }

        curl_close($curl);

        return $data;
    }
}
