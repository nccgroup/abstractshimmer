# ABSTRACT SHIMMER (CVE-2020-15257)

This repo contains proof-of-concept exploit code for CVE-2020-15257 as
described in [our blog post](https://research.nccgroup.com/2020/12/10/abstract-shimmer-cve-2020-15257-host-networking-is-root-equivalent-again/).
While written for containerd 1.2.x and 1.3.x, it should work on pre-patch
versions of containerd 1.4.x.

```
$ go build
```

```
$ docker build -t abstractshimmer .
$ docker run --rm -d --network host abstractshimmer | xargs docker logs -f
```

```
$ cat /tmp/shimmer.out
$ cat /tmp/shimmer.binary
$ # or, for containerd 1.2.x
$ cat /etc/crontab
```

***Note:*** This exploit will leave Docker/containerd a bit out of sorts. There
will be a dangling containerd-shim and Docker container that need to be killed
and `docker rm --force`'d respectively to clean things up a bit.
/var/lib/containerd/io.containerd.runtime.v1.linux/moby/ and
/run/containerd/io.containerd.runtime.v1.linux/moby/ will have some leftovers
as well. As part of this, this exploit does not attempt to reconcile
containerd's `address` files. This may lead to issues where attempting to
update a vulnerable system after exploiting it will result in Docker/containerd
failing to restart cleanly and/or being unable to see existing containers. If
you observe this while updating your containerd package, it may be an indicator
that the system has been previously compromised by some variant of this
exploit.
