<?php

/*
 * This file is part of the SensioLabs Security Checker.
 *
 * (c) Fabien Potencier
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SensioLabs\Security\Crawler;

use SensioLabs\Security\Exception\RuntimeException;

/**
 * @internal
 */
abstract class BaseCrawler implements CrawlerInterface
{
    protected $endPoint = 'https://security.sensiolabs.org/check_lock';
    protected $timeout = 20;
    protected $excludedCVEs = array();

    /**
     * {@inheritdoc}
     */
    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    /**
     * {@inheritdoc}
     */
    public function setEndPoint($endPoint)
    {
        $this->endPoint = $endPoint;
    }

    /**
     * {@inheritdoc}
     */
    public function setExcludedCVEs(array $cves)
    {
        $this->excludedCVEs = $cves;
    }

    /**
     * {@inheritdoc}
     */
    public function check($lock)
    {
        $certFile = $this->getCertFile();

        try {
            list($headers, $body) = $this->doCheck($lock, $certFile);
        } catch (\Exception $e) {
            if (__DIR__.'/../Resources/security.sensiolabs.org.crt' !== $certFile) {
                unlink($certFile);
            }

            throw $e;
        }

        if (!(preg_match('/X-Alerts: (\d+)/', $headers, $matches) || 2 == count($matches))) {
            throw new RuntimeException('The web service did not return alerts count.');
        }

        $vulnerabilityCount = (int) $matches[1];
        $vulnerabilities = json_decode($body, true);

        return $this->filterOutExcludedCVEs($vulnerabilityCount, $vulnerabilities);
    }

    /**
     * @return array An array where the first element is a headers string and second one the response body
     */
    abstract protected function doCheck($lock, $certFile);

    protected function getLockContents($lock)
    {
        $contents = json_decode(file_get_contents($lock), true);
        $packages = array('packages' => array(), 'packages-dev' => array());
        foreach (array('packages', 'packages-dev') as $key) {
            if (!is_array($contents[$key])) {
                continue;
            }
            foreach ($contents[$key] as $package) {
                $data = array(
                    'name' => $package['name'],
                    'version' => $package['version'],
                );
                if (isset($package['time']) && false !== strpos($package['version'], 'dev')) {
                    $data['time'] = $package['time'];
                }
                $packages[$key][] = $data;
            }
        }

        return json_encode($packages);
    }

    private function getCertFile()
    {
        $certFile = __DIR__.'/../Resources/security.sensiolabs.org.crt';
        if ('phar://' !== substr(__FILE__, 0, 7)) {
            return $certFile;
        }

        $tmpFile = tempnam(sys_get_temp_dir(), 'sls');
        if (false === @copy($certFile, $tmpFile)) {
            throw new RuntimeException(sprintf('Unable to copy the certificate in "%s".', $tmpFile));
        }

        return $tmpFile;
    }

    private function filterOutExcludedCVEs($vulnerabilityCount, $vulnerabilities)
    {
        foreach ($vulnerabilities as $package => $overview) {
            foreach ($overview['advisories'] as $yaml => $advisory) {
                if (in_array($advisory['cve'], $this->excludedCVEs)) {
                    unset($vulnerabilities[$package]['advisories'][$yaml]);
                    $vulnerabilityCount--;
                }
            }
        }

        // Account for packages for which we excluded all related CVEs.
        foreach ($vulnerabilities as $package => $overview) {
            if (empty($overview['advisories'])) {
                unset($vulnerabilities[$package]);
            }
        }

        return array($vulnerabilityCount, $vulnerabilities);
    }
}
