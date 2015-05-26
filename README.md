SensioLabs Security Checker
===========================

The SensioLabs Security Checker is a command line tool that checks if your
application uses dependencies with known security vulnerabilities. It uses the
[SensioLabs Security Check Web service][1] and the [Security Advisories Database][2].

Usage
-----

Download the [security-checker.phar][3] file:

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
        $alerts = $checker->check('/path/to/composer.lock');

[1]: http://security.sensiolabs.org/
[2]: https://github.com/FriendsOfPHP/security-advisories
[3]: http://get.sensiolabs.org/security-checker.phar
