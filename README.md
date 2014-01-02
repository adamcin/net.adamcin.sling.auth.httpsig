net.adamcin.sling.auth.httpsig
==============================

HTTP Signature Authentication Handler implementation for Apache Sling using SSH authorized_keys.

How It Works
============

1. Install the following bundles:
  * [net.adamcin.httpsig.osgi](http://search.maven.org/#artifactdetails%7Cnet.adamcin.httpsig%7Cnet.adamcin.httpsig.osgi%7C1.0.2%7Cbundle): HTTP Signature Implementation for Java
  * [net.adamcin.sling.auth.httpsig](http://search.maven.org/#artifactdetails%7Cnet.adamcin.sling%7Cnet.adamcin.sling.auth.httpsig%7C0.8.0%7Cbundle): Sling HTTP Signature Authentication Handler

1. Deploy an authorized_keys file containing the SSH public keys of clients who are authorized to login as admin, such as that of a Jenkins server, to either of the two locations on the server filesystem:
  * ${sling.home}/../.ssh/authorized_keys: Deploy to this location to only grant HTTP admin permission to client public keys. Notice that the .ssh directory in the path is a **sibling** of ${sling.home}, which allows for re-installation and backup/restore of the Sling instance without disturbing the authorized_keys file. This file takes precedence over the standard user home location.
  * ${user.home}/.ssh/authorized_keys: Deploy to this location only in order to grant ssh/scp access to clients with these public keys, in addition to granting them HTTP admin authentication.

1. Use a Signature-enabled HTTP client to interact with the Sling instance, with a keyId format following the Joyent convention of "/$username/keys/$fingerprint". You can find Java-based helpers in [httpsig-java](https://github.com/adamcin/httpsig-java) for Apache Commons HttpClient 3.x, Apache Http Components 4.x, and Ning AsyncHttpClient.

[![Analytics](https://ga-beacon.appspot.com/UA-37073514-2/net.adamcin.sling.auth.httpsig/blob/master/README.md)](https://github.com/igrigorik/ga-beacon)
