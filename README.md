# UndeadPKI

This project was written at WebTrends in 2015 while decommissioning a legacy CA.  The CA's hardare failed and we chose to not resurrect it, however we still needed to maintain a basic level of functionality while we migrated dependent clients and applications to its replacement.  This script uses OpenSSL to generate a cache of pre-computed CRLs to be published on a schedule, allowing us to revoke certificates if necessary prior to the full removal of the CA from AD.
