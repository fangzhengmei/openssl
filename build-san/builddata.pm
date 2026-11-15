package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    @PREFIX
    @libdir
    @BINDIR @BINDIR_REL_PREFIX
    @LIBDIR @LIBDIR_REL_PREFIX
    @INCLUDEDIR @INCLUDEDIR_REL_PREFIX
    @APPLINKDIR @APPLINKDIR_REL_PREFIX
    @MODULESDIR @MODULESDIR_REL_LIBDIR
    @PKGCONFIGDIR @PKGCONFIGDIR_REL_LIBDIR
    @CMAKECONFIGDIR @CMAKECONFIGDIR_REL_LIBDIR
    $COMMENT $VERSION @LDLIBS
);

our $COMMENT                    = 'This file should be used when building against this OpenSSL build, and should never be installed';
our @PREFIX                     = ( '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san' );
our @libdir                     = ( '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san' );
our @BINDIR                     = ( '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san/apps' );
our @BINDIR_REL_PREFIX          = ( 'apps' );
our @LIBDIR                     = ( '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san' );
our @LIBDIR_REL_PREFIX          = ( '' );
our @INCLUDEDIR                 = ( '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san/include', '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san/../include' );
our @INCLUDEDIR_REL_PREFIX      = ( 'include', '../include' );
our @APPLINKDIR                 = ( '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san/ms' );
our @APPLINKDIR_REL_PREFIX      = ( 'ms' );
our @MODULESDIR                 = ( '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san/providers' );
our @MODULESDIR_REL_LIBDIR      = ( 'providers' );
our @PKGCONFIGDIR               = ( '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san' );
our @PKGCONFIGDIR_REL_LIBDIR    = ( '' );
our @CMAKECONFIGDIR             = ( '/srv/fb2/fangzhengmei/0066-openssl-7-ce0f1d96/build-san' );
our @CMAKECONFIGDIR_REL_LIBDIR  = ( '' );
our $VERSION                    = '4.2.0-dev';
our @LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    $^O eq 'VMS'
    ? split(/ *, */, '-ldl -pthread ')
    : split(/ +/, '-ldl -pthread ');

1;
