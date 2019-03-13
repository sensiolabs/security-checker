SensioLabs Security Checker
===========================

The SensioLabs Security Checker is a command line tool that checks if your
application uses dependencies with known security vulnerabilities. It uses the
[Security Check Web service][1] and the [Security Advisories Database][2].

**TIP**: As an alternative, you can use the [Symfony CLI][3] tool that has the
following advantages: it does not depend on PHP, all checks are done locally (no
calls to the security.symfony.com API):

    $ symfony security:check

Usage
-----

Download the [security-checker.phar][4] file:

    $ php security-checker.phar security:check /path/to/composer.lock

Use the code from the repository directly:

    $ composer install
    $ php security-checker security:check /path/to/composer.lock

Integration
-----------

The checker uses the Symfony Console component; so, you can easily integrate
the checker into your own project:

 * by using the `SecurityCheckerCommand` class into your Symfony Console
   application;

 * by using the `SecurityChecker` class directly into your own code:

        use SensioLabs\Security\SecurityChecker;

        $checker = new SecurityChecker();
        $result = $checker->check('/path/to/composer.lock', 'json');
        $alerts = json_decode((string) $result, true);

[1]: https://security.symfony.com/
[2]: https://github.com/FriendsOfPHP/security-advisories
[3]: https://symfony.com/download
[4]: https://get.sensiolabs.org/security-checker.phar
