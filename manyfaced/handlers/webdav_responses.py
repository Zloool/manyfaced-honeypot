"""WebDAV response content templates.

Extracted from webdav_handler.py to reduce line count and cyclomatic complexity.
All functions return pre-built HTML/XML strings for WebDAV honeypot responses.
"""

from datetime import datetime, timezone


def directory_listing(path: str) -> str:
    """Generate a WebDAV directory listing page."""
    dir_name = path.rstrip('/').split('/')[-1] or 'webdav'
    now = datetime.now(timezone.utc).strftime('%d %b %Y %H:%M:%S GMT')

    return f"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /{dir_name}</title>
 </head>
 <body>
<h1>Index of /{dir_name}</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a>       </td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="documents/">documents/</a>                </td><td align="right">{now}</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="uploads/">uploads/</a>                    </td><td align="right">{now}</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="shared/">shared/</a>                     </td><td align="right">{now}</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="config/">config/</a>                     </td><td align="right">{now}</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href=".htaccess">.htaccess</a>                   </td><td align="right">{now}</td><td align="right"> 128 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href=".htpasswd">.htpasswd</a>                   </td><td align="right">{now}</td><td align="right"> 256 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="index.php">index.php</a>                   </td><td align="right">{now}</td><td align="right"> 4096 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="server.php">server.php</a>                  </td><td align="right">{now}</td><td align="right"> 8192 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="upload.php">upload.php</a>                  </td><td align="right">{now}</td><td align="right"> 2048 </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="download.php">download.php</a>                </td><td align="right">{now}</td><td align="right"> 1024 </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.57 (Ubuntu) Server at webdav.example.com Port 80</address>
</body>
</html>"""


def propfind_response(path: str) -> str:
    """Generate a WebDAV PROPFIND XML response."""
    dir_name = path.rstrip('/').split('/')[-1] or 'webdav'
    now = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')

    def _resource(href: str, name: str) -> str:
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        return (
            f'  <d:response>\n'
            f'    <d:href>{href}</d:href>\n'
            f'    <d:propstat>\n'
            f'      <d:status>HTTP/1.1 200 OK</d:status>\n'
            f'      <d:prop>\n'
            f'        <d:creationdate>{ts}</d:creationdate>\n'
            f'        <d:displayname>{name}</d:displayname>\n'
            f'        <d:getcontentlength>0</d:getcontentlength>\n'
            f'        <d:getlastmodified>{now}</d:getlastmodified>\n'
            f'        <d:resourcetype>\n'
            f'          <d:collection/>\n'
            f'        </d:resourcetype>\n'
            f'      </d:prop>\n'
            f'    </d:propstat>\n'
            f'  </d:response>'
        )

    return f"""<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:ns0="http://apache.org/dav/props/" xmlns:ns1="DAV:">
  <d:response>
    <d:href>/</d:href>
    <d:propstat>
      <d:status>HTTP/1.1 200 OK</d:status>
      <d:prop>
        <d:creationdate>{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}</d:creationdate>
        <d:displayname>webdav</d:displayname>
        <d:getcontentlength>0</d:getcontentlength>
        <d:getlastmodified>{now}</d:getlastmodified>
        <d:resourcetype>
          <d:collection/>
        </d:resourcetype>
        <d:supportedlock>
          <d:lockentry>
            <d:lockscope>
              <d:exclusive/>
            </d:lockscope>
            <d:locktype>
              <d:write/>
            </d:locktype>
          </d:lockentry>
          <d:lockentry>
            <d:lockscope>
              <d:shared/>
            </d:lockscope>
            <d:locktype>
              <d:write/>
            </d:locktype>
          </d:lockentry>
        </d:supportedlock>
        <d:lockdiscovery/>
        <ns0:readable/>
        <ns0:writable/>
      </d:prop>
    </d:propstat>
  </d:response>
{_resource(f'/{dir_name}/documents/', 'documents')}
{_resource(f'/{dir_name}/uploads/', 'uploads')}
{_resource(f'/{dir_name}/shared/', 'shared')}
{_resource(f'/{dir_name}/config/', 'config')}
</d:multistatus>"""


def webdav_portal_page() -> str:
    """WebDAV portal/index page."""
    return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>WebDAV Server</title>
 </head>
 <body>
<h1>WebDAV Server</h1>
<p>This is a WebDAV server. Use a WebDAV client to connect.</p>
<p>Supported methods: GET, HEAD, POST, OPTIONS, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, PUT, DELETE</p>
<p>Try using <code>PROPFIND</code> to list directories or <code>PUT</code> to upload files.</p>
<p><a href="/">/</a> | <a href="/webdav/">/webdav/</a> | <a href="/dav/">/dav/</a></p>
<address>Apache/2.4.57 (Ubuntu) Server with mod_dav</address>
</body>
</html>"""


def webdav_login_page() -> str:
    """WebDAV login page."""
    return """<!DOCTYPE html>
<html>
<head>
    <title>WebDAV - Authentication Required</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; text-align: center; padding: 50px; }
        .container { background: white; padding: 30px; border-radius: 8px; max-width: 400px; margin: 0 auto; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { color: #333; }
        .form-group { margin-bottom: 15px; text-align: left; }
        label { display: block; margin-bottom: 5px; color: #555; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        input[type="submit"] { background: #007cba; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; width: 100%; }
    </style>
</head>
<body>
<div class="container">
    <h2>WebDAV Server Authentication</h2>
    <p>Please enter your credentials to access this WebDAV share.</p>
    <form method="POST" action="/webdav/login/">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" name="username" id="username">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" name="password" id="password">
        </div>
        <div class="form-group">
            <input type="submit" value="Login">
        </div>
    </form>
</div>
</body>
</html>"""


def login_failed_response() -> str:
    """WebDAV login failed response body."""
    return """<!DOCTYPE html>
<html>
<head>
    <title>WebDAV - Authentication Failed</title>
</head>
<body>
<h2>Authentication Failed</h2>
<p>Invalid credentials. Please try again.</p>
<p><a href="/webdav/">Return to WebDAV</a></p>
</body>
</html>"""


def forbidden_response() -> str:
    """403 Forbidden response body."""
    return """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>403 Forbidden</title>
 </head>
 <body>
<h1>403 Forbidden</h1>
<p>You don't have permission to access this file.</p>
</body>
</html>"""
