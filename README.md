# UndeadPKI

This project was written at WebTrends in 2015 while decommissioning a legacy CA.  The CA's hardare failed and we chose to not resurrect it, however we still needed to maintain a basic level of functionality while we migrated dependent clients and applications to its replacement.  This script uses OpenSSL to generate a CRL and publishes it to AD.  I later extended it to generate a cache of "future" CRLs and publish them on a schedule to avoid having to keep the old CA's private key on disk, however that work was lost.
