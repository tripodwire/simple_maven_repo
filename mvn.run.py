#! /usr/bin/env python


import os
import subprocess
import click
import re
import posixpath
import urllib
import time
import traceback
import sys
import glob
import base64
import json
import ssl
from concurrent.futures import ThreadPoolExecutor
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

__version__ = "0.1"
__all__ = ["HTTPMavenServer", "HTTPMavenRequestHandler"]


# noinspection PyPep8Naming
class HTTPMavenRequestHandler(SimpleHTTPRequestHandler):
    secure_put = False
    check_existence = True
    ignore_existence = [re.compile("^maven-metadata\.xml", re.IGNORECASE)]
    jar_binary = None
    repository = None
    repository_name = None
    pool = ThreadPoolExecutor(1)
    indexer_jar = "indexer-cli-5.1.1.jar"
    jar_locations = [os.path.join(os.path.dirname(__file__), indexer_jar),
                     os.path.join(os.getcwd(), indexer_jar),
                     indexer_jar]
    basic_authorizations = []

    @classmethod
    def add_auth(cls, auth):
        cls.basic_authorizations.append(auth)

    @classmethod
    def add_auth_from_clear(cls, username, password):
        cls.add_auth(base64.b64encode("%s:%s" % (username, password)))

    @classmethod
    def set_repository(cls, repo, repo_name=None):
        if repo_name:
            cls.repository_name = repo_name
        if repo and os.path.exists(repo):
            cls.repository = repo
            if not cls.repository_name:
                cls.repository_name = os.path.basename(cls.repository)
            os.chdir(cls.repository)

    @classmethod
    def add_location(cls, location):
        if location and os.path.exists(location):
            cls.jar_locations.append(location)

    @classmethod
    def optimize_locations_and_setup_binary(cls):
        for location in cls.jar_locations:
            if os.path.exists(location):
                cls.jar_binary = location
                break

    @classmethod
    def add_and_optimize(cls, location):
        cls.add_location(location)
        cls.optimize_locations_and_setup_binary()

    @classmethod
    def existence_ignored(cls, path):
        bpath = os.path.basename(path)
        for pattern in cls.ignore_existence:
            if pattern.findall(bpath):
                return True
        return False

    def translate_path(self, path):
        """Translate a /-separated PATH to the local filename syntax.

        Components that mean special things to the local file system
        (e.g. drive or directory names) are ignored.  (XXX They should
        probably be diagnosed.)

        """
        # abandon query parameters
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        # Don't forget explicit trailing slash when normalizing. Issue17324
        trailing_slash = path.rstrip().endswith('/')
        path = posixpath.normpath(urllib.unquote(path))
        words = path.split('/')
        words = filter(None, words)
        path = self.repository
        for word in words:
            if os.path.dirname(word) or word in (os.curdir, os.pardir):
                # Ignore components that are not a simple file/directory name
                continue
            path = os.path.join(path, word)
        if trailing_slash:
            path += '/'
        return path

    def send_auth(self, *args):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Maven Repo\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        if args:
            for arg in args:
                self.wfile.write("%s" % arg)

    def is_authorized(self, authorization):
        for auth in self.basic_authorizations:
            if authorization == 'Basic %s' % auth:
                return True
        return False

    def do_PUT(self):
        if not self.secure_put:
            self.handle_put()
        else:
            """
                Present user authentication.
            """
            authorization_header = self.headers.getheader('Authorization')
            if authorization_header is None:
                self.send_auth('no auth header received')
            elif self.is_authorized(authorization_header):
                self.handle_put()
            else:
                self.send_auth(authorization_header, 'not authenticated')

    def handle_put(self):
        length = int(self.headers['Content-Length'])
        if length > 0:
            path = self.translate_path(self.path)

            if self.check_existence and not self.existence_ignored(path):
                # If the resource already exists
                if os.path.exists(path):
                    self.send_response(409)
                    self.end_headers()
                    return

            # create a resource
            content = self.rfile.read(length)
            with self._file_handle(path) as fd:
                fd.write(content)
            self.send_response(201)
            self.end_headers()
            self.run_indexer(path)
            return

        # If we get here, error out
        self.send_error(400)

    @staticmethod
    def _file_handle(path):
        try:
            dirname = os.path.dirname(path)
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname)
            return open(path, 'wb+')
        except Exception as e:
            print "Error: %s : %s" % (e.message, type(e).__name__)

    @classmethod
    def run_indexer(cls, path):
        if path and path.endswith(".jar") and cls.jar_binary and os.path.exists(cls.jar_binary):
            cls.run_index_impl()

    @classmethod
    def run_index_impl(cls):
        cls.pool.submit(cls.__run_index_impl_main__)

    @classmethod
    def __run_index_impl_main__(cls):
        try:
            max_count = 10000
            time.sleep(10)
            destination = os.path.join(cls.repository, ".index")
            msg = "\r\nIndexing mvn repo ( %s ) -> ( %s )" % (cls.repository, destination)
            sys.stderr.write(msg)
            p = subprocess.Popen(["java",
                                  "-jar", cls.jar_binary,
                                  "-n", cls.repository_name,
                                  "-i", destination,
                                  "-r", cls.repository,
                                  "-d", destination,
                                  "-t", "full"],
                                 stderr=subprocess.PIPE, cwd=cls.repository)
            counter = 0
            while True:
                counter += 1
                err = p.stderr.read(1)
                if err == '' and p.poll() is not None:
                    break
                if err != '':
                    sys.stderr.write(err)
                    sys.stderr.flush()
                # extreme cases
                if counter > max_count:
                    break
            sys.stderr.write("\n")
        except Exception as e:
            sys.stderr.write("Error: %s" % e)
            sys.stderr.write(traceback.print_exc())

    @classmethod
    def ensure_index(cls):
        index_path = os.path.join(cls.repository, ".index", "nexus-maven-repository-index*")
        if not glob.glob(index_path):
            print "Running indexer to create the index"
            cls.run_index_impl()

    @classmethod
    def params(cls):
        return "repository_name: %s\nrepository: %s\nindexer_jar: %s\nsecure_put: %s\n" % \
               (cls.repository_name, cls.repository, cls.jar_binary, cls.secure_put)

    do_POST = SimpleHTTPRequestHandler.do_GET
    do_DELETE = SimpleHTTPRequestHandler.do_GET
    do_OPTIONS = SimpleHTTPRequestHandler.do_GET
    do_PATCH = SimpleHTTPRequestHandler.do_GET


class HTTPMavenServer(HTTPServer):
    def __init__(self, server_address, repository, repository_name=None, jar_location=None, secure_put=None,
                 auths=None, certificate=None):
        HTTPMavenRequestHandler.protocol_version = "HTTP/1.0"
        HTTPMavenRequestHandler.add_and_optimize(jar_location)
        if secure_put is not None:
            HTTPMavenRequestHandler.secure_put = secure_put
        if isinstance(auths, (list, tuple)):
            for auth in auths:
                HTTPMavenRequestHandler.add_auth(auth)
        if not repository or not os.path.exists(repository) or not os.path.isdir(repository):
            raise Exception("Repository must be provided and must be a valid directory and maven repo!")
        HTTPMavenRequestHandler.set_repository(repository, repository_name)

        # use ssl?
        self.use_ssl = False
        if certificate and os.path.exists(certificate):
            self.use_ssl = True
            if int(server_address[1]) == 80:
                server_address[1] = 443
        #
        HTTPServer.__init__(self, server_address, HTTPMavenRequestHandler, True)
        self.certificate = certificate
        if self.use_ssl:
            self.socket = ssl.wrap_socket(self.socket, server_side=True, certfile=self.certificate)

    def params(self):
        params = HTTPMavenRequestHandler.params()
        if self.use_ssl:
            params = "%scertificate: %s\n" % (params, self.certificate)
        return params


########################
# COMMAND LINE
########################

default_port = 9090
default_ip = ''


@click.command(help='Runs a simple maven repo ...',
               context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--repo', help='The maven repository base path', required=True)
@click.option('--reponame', help='Repository name if it is different than the repo directory name')
@click.option('--jar', help='Location of the maven indexer jar')
@click.option('--port', help='The http port to bind to, defaults to %s' % default_port, type=int)
@click.option('--ip', help='The ip address to bind to, inherits the underlying socket address if not set')
@click.option('--config', help='Config file: all arguments can also be specified in config file',
              type=click.Path(exists=True))
@click.option('--secure-put', help='Authorize all PUT modification requests', is_flag=True)
@click.option('--cert', help='Location of ssl certificate to use if HTTPS is desired', type=click.Path(exists=True))
@click.option('--auths', multiple=True,
              help='Optional, base 64 encoded basic header authorizations. It can be specified multiple times')
def main(repo, reponame, jar, port, ip, config, secure_put, cert, auths):
    """
    Run a simple HTTP maven repo
    :param repo:
    :param reponame:
    :param jar:
    :param port:
    :param ip:
    :param config:
    :param secure_put:
    :param cert:
    :param auths:
    :return:
    """
    # store valid params from locals to facilitate override of config
    parameters = dict((k, v) for k, v in locals().iteritems() if v)
    args = dict(port=default_port, ip=default_ip)
    # if a JSON config file exists, consider the values
    if config and os.path.exists(config):
        with open(config) as c:
            j = json.load(c)
            if isinstance(j, dict):
                # resolve the clear auths
                clear_auths = j.get("clear_auths", {}) or {}
                local_auths = j.get("auths", []) or []
                j.pop('auths', None)
                j.pop('clear_auths', None)
                if clear_auths and isinstance(clear_auths, dict):
                    for ck, cv in clear_auths.iteritems():
                        local_auths.append(base64.b64encode("%s:%s" % (ck, cv)))
                j['auths'] = tuple(local_auths)
                j = dict((k, v) for k, v in j.iteritems() if v)
                args.update(j)
    # command line args overrides config
    args.update(parameters)
    #
    httpd = HTTPMavenServer((args.get('ip', ip), int(args.get('port', port))),
                            repository=args.get('repo', repo),
                            repository_name=args.get('reponame', reponame),
                            jar_location=args.get('jar', jar),
                            secure_put=args.get('secure_put', secure_put),
                            auths=args.get('auths', auths),
                            certificate=args.get('cert', cert))

    # do cleanup
    def shutdown():
        httpd.socket.close()
        HTTPMavenRequestHandler.pool.shutdown()

    try:
        sa = httpd.socket.getsockname()
        print "Serving HTTP on", sa[0], "port", sa[1], "..."
        print httpd.params()
        HTTPMavenRequestHandler.ensure_index()
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write('^C received, shutting down the web server and executor pools')
    finally:
        shutdown()


if __name__ == '__main__':
    main()
