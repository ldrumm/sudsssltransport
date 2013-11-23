import suds
import requests

from suds.transport.http import Transport, Reply, Request, TransportError
from requests import HTTPError, RequestException, ConnectionError
from requests.exceptions import SSLError
from StringIO import StringIO
"""
suds does not verify the host when connecting over https.  
This is due to a deficiency in urllib2.
This module overrides the standard suds transport with one based on requests 
and ensures that when connecting over SSL, the certificate is verified."""

class SudsClientStrictSSL(suds.client.Client):
    def __init__(self, url, **kwargs):
        with _StrictSSLHTTPTransportAuthenticated(**kwargs) as transport:
            kwargs = transport.suds_kwargs
            kwargs.update({'transport' : transport})
            suds.client.Client.__init__(self, url, **kwargs)

class _StrictSSLHTTPTransportAuthenticated(Transport):

    def __init__(self, **kwargs):
        #from requests.request: ' optional) if ``True``, the SSL cert will be verified. A CA_BUNDLE path can also be provided.
        self.verify_ssl = kwargs.get('verify_ssl', True)
        #from requests.request: '(optional) if String, path to ssl client cert file (.pem). If Tuple, ('cert', 'key') pair.'
        self.client_cert = kwargs.get('client_cert', None)
        self.username = kwargs.get('username', None)
        self.password = kwargs.get('password', None)
        #This option rewrites all paths given by a WSDL to HTTPS
        #useful only when you know the WSDL shouldn't be handing you HTTP
        self.rewrite_to_https = kwargs.get('rewrite_to_https', False)
        self.proxy = kwargs.get('proxy', {})
        self.suds_kwargs = {key: value for key, value in kwargs.items() if key not in 
            ('username','password', 'client_cert', 'verify_ssl', 'proxy', 'rewrite_to_https')}
        Transport.__init__(self, **self.suds_kwargs)
        self.session = requests.Session()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        """clean up on object destruction"""
        self.session.close()
    
    def __del__(self, *args):
        """clean up on object destruction"""
        self.session.close()
        
    def open(self, request):
        """
        Perform an HTTP GET to the URL in the given suds.transport.Request and returns
        a file-like object of the request body.
        """
        response = None
        try:
            if self.verify_ssl and request.url.startswith('http://'):
                if self.rewrite_to_https:
                    request.url = 'https://' + request.url[7:]
                else:
                    raise SSLError("can't verify SSL certificate with plain HTTP link")
            response = self.session.get(
                url=request.url, 
                data=request.message,
                headers=request.headers,
                proxies=self.proxy,
                verify=self.verify_ssl,
                cert=self.getclientcertificate(),
            )
            response.raise_for_status()
        except SSLError as e:
            raise TransportError(e.message, None)
        except (RequestException, HTTPError, ConnectionError) as e:
            raise TransportError(str(e), None)
        return StringIO(response.text)
    
    def send(self, request):
        """converts the suds request into requests.request and HTTP POSTs 
        to the url given in the @request.
        If verify_ssl is True, then performs some additional checks to make sure 
        SSL is being handled in a sane fashion."""
        result = None
        try:
            if self.verify_ssl and request.url.startswith('http://'):
                if self.rewrite_to_https:
                    request.url = 'https://' + request.url[7:]
                else:
                    raise SSLError("can't verify SSL certificate with plain HTTP link")
#                
            response = self.session.post(
                url=request.url,
                headers=request.headers,
                data=request.message,
                proxies=self.proxy,
                verify=self.verify_ssl,
                auth=self.getcredentials(),
                cert=self.getclientcertificate()
            )
            result = Reply(response.status_code, response.headers, response.text)
            response.raise_for_status()
            if response.status_code == 401:
                #TODO do something useful
                raise TransportError(response.status_code)
        
        except SSLError as e:
            raise TransportError(e.message, None)    
        
        except (HTTPError, ConnectionError, RequestException) as e:
            if e.response.status_code in (202, 204):
                result = None
            else:
                raise TransportError(str(e), e.response.status_code, StringIO(e.response.content))
        return result  
    
    #This method could be overridden to get credentials from an external service
    def getcredentials(self):
        """returns a tuple of @username @password used for HTTP basic authorisation."""
        return (self.username, self.password)
    
    #This method could be overridden to e.g. search / 
    #create a pem from a list of files making up a chain  
    def getclientcertificate(self):
        """stub method that simply returns @self.client_cert"""
        return self.client_cert 

