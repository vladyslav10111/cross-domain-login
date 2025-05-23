<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit7c3d35c8133600c5ea98c5c7cf8c3122
{
    public static $prefixLengthsPsr4 = array (
        'V' => 
        array (
            'Vladyslav10111\\CrossDomainLogin\\' => 32,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Vladyslav10111\\CrossDomainLogin\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit7c3d35c8133600c5ea98c5c7cf8c3122::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit7c3d35c8133600c5ea98c5c7cf8c3122::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit7c3d35c8133600c5ea98c5c7cf8c3122::$classMap;

        }, null, ClassLoader::class);
    }
}
