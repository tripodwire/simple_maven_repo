
<style>
pre, xmp, plaintext, listing {
    white-space: pre;
}
.markdown-body pre > code {
    white-space: pre;
}
.markdown-body code {
    white-space: nowrap;
}
</style>


# Simple Maven Repository

A simple maven HTTP repository server implementation written in python.

<pre>

Usage: mvn.run.py [OPTIONS]

  Runs a simple maven repo ...

Options:
  --repo TEXT      The maven repository base path  [required]
  --reponame TEXT  Repository name if it is different than the repo directory
                   name
  --jar TEXT       Location of the maven indexer jar
  --port INTEGER   The http port to bind to, defaults to 9090
  --ip TEXT        The ip address to bind to, inherits the underlying socket
                   address if not set
  --config PATH    JSON Config file: all arguments can also be specified in
                   config file
  --secure-put     Authorize all PUT modification requests
  --cert PATH      Location of ssl certificate to use if HTTPS is desired
  --auths TEXT     Optional, base 64 encoded basic header authorizations. It
                   can be specified multiple times
  -h, --help       Show this message and exit.

  
</pre>