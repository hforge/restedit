#!/usr/bin/env python
##############################################################################
#
# Copyright (c) 2001, 2002 Zope Corporation and Contributors.
# Copyright (c) 2010 David Versmisse <david.versmisse@itaapy.com>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Restedit, an External Editor Helper Application based on zopeedit.py:
http://plone.org/products/zope-externaleditor-client"""

import sys
win32 = sys.platform == 'win32'

if win32:
    # import pywin32 stuff first so it never looks into system32
    import pythoncom, pywintypes
    from win32process import CreateProcess, GetExitCodeProcess, STARTUPINFO
    from _winreg import HKEY_LOCAL_MACHINE, OpenKey, EnumKey, QueryValueEx

    # prevent warnings from being turned into errors by py2exe
    import warnings
    warnings.filterwarnings('ignore')

import os, re, popen2
import time
import traceback
import logging
import urllib
import shutil
import glob

from base64 import decodestring as decode_base64
from datetime import datetime
from time import sleep, mktime
from ConfigParser import ConfigParser
from optparse import OptionParser
from os import tempnam, remove, chmod, system, startfile
from os.path import exists, expanduser, getmtime
from tempfile import mktemp
from urllib2 import parse_http_list, parse_keqv_list, Request, build_opener
from urllib2 import HTTPBasicAuthHandler, HTTPDigestAuthHandler
from urllib2 import HTTPPasswordMgrWithDefaultRealm, HTTPError
from urlparse import urlparse
from email.utils import parsedate_tz, mktime_tz, formatdate



# Constantes / global variables
__version__ = '1.0.0'
TK_TITLE = "Restedit"
LOG_LEVELS = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}
logger = logging.getLogger('restedit')
log_file = None



class Configuration:

    def __init__(self):
    	if win32:
            path = expanduser('~\\Restedit.ini')
        else:
            path = expanduser('~/.resteditrc')
        self.path = path

	# No file, we create a new one
	if not exists(path):
            f = open(path, 'w')
            f.write(get_default_configuration())
            f.close()

	# And read it
        self.config = ConfigParser()
        self.config.readfp(open(path))

        logger.info("init at: %s" % time.asctime(time.localtime()) )


    def save(self):
        """Save config options to disk"""
        self.config.write(open(self.path, 'w'))
        logger.info("save at: %s" % time.asctime(time.localtime()) )


    def set(self, section, option, value):
        self.config.set(section, option, value)


    def __getattr__(self, name):
        # Delegate to the ConfigParser instance
        return getattr(self.config, name)


    def getAllOptions(self, content_type, title, host_domain):
        """Return a dict of all applicable options for the
           given content_type and host_domain
        """
        opt = {}
        sep = content_type.find('/')
        general_type = '%s/*' % content_type[:sep]

        # Divide up the domains segments and create a
        # list of domains from the bottom up
        host_domain = host_domain.split('.')
        domains = []
        for i in range(len(host_domain)):
            domains.append('domain:%s' % '.'.join(host_domain[i:]))
        domains.reverse()

        sections = ['general']
        sections.extend(domains)
        sections.append('general-type:%s' % general_type)
        sections.append('content-type:%s' % content_type)
        sections.append('title:%s' % title)

        for section in sections:
            if self.config.has_section(section):
                for option in self.config.options(section):
                    opt[option] = self.config.get(section, option)
                    logger.debug("option %s: %s" %( option, opt[option]))
        return opt



class ExternalEditor:

    tried_cleanup = False

    def __init__(self, input_filename=None):
        """If input_filename = None => Edit config"""

        self.opener = None

        # Setup logging
        global log_file
        log_file = mktemp(suffix='-restedit-log.txt')
        log_filehandler = logging.FileHandler(log_file)
        log_formatter = logging.Formatter(
                                '%(asctime)s %(levelname)s %(message)s')
        log_filehandler.setFormatter(log_formatter)
        logger.addHandler(log_filehandler)
        logger.setLevel(logging.DEBUG)

        logger.info('Restedit version %s maintained by Itaapy.' % __version__ )
        logger.info('Opening %r.', input_filename)

        try:
            # If there is no filename, the user edits the config file of
            # restedit
            if input_filename is None:
                self.edit_config()
                sys.exit(0)

            # Open the configuration file
            self.config = Configuration()

            # Open the input file and read the metadata headers
            input_file = open(input_filename, 'rb')

            self.metadata = metadata = read_metadata(input_file)
            logger.debug("metadata: %s" % repr(self.metadata))

            # Get the url, host and path
            self.url = metadata['url']
            _, self.host, self.path = urlparse(metadata['url'])[:3]

            # Get last-modified
            last_modified = metadata['last-modified']
            self.last_modified = http_date_to_datetime(last_modified)
            logger.debug('last_modified: %s' % str(self.last_modified))

            # Get all configuration options
            self.options = self.config.getAllOptions(
                                            metadata.get('content_type',''),
                                            metadata.get('title',''),
                                            self.host)
            # Log level
            logger.setLevel(LOG_LEVELS[self.options.get('log_level','info')])

            logger.info("all options : %r" % self.options)

            # lock file name for editors that create a lock file
            self.lock_file_schemes = self.options.get('lock_file_schemes',
                                                      '').split(';')

            # Should we keep the log file?
            self.keep_log = int(self.options.get('keep_log', 1))

            # Should we clean-up temporary files ?
            self.clean_up = int(self.options.get('cleanup_files', 1))

            self.save_interval = float(self.options.get('save_interval',5))
            self.max_is_alive_counter = int(
                                    self.options.get('max_isalive_counter', 5))

            # Server charset
            self.server_charset = self.options.get('server_charset', 'utf-8')

            # Client charset
            self.client_charset = self.options.get('client_charset',
                                                   'iso-8859-1')

            # Retrieve original title
            self.title = (metadata["title"].decode(self.server_charset)
                          .encode(self.client_charset,'ignore'))

            # Write the body of the input file to a separate file
            if int(self.options.get('long_file_name', 0)):
                sep = self.options.get('file_name_separator', ',')
                content_file = urllib.unquote('-%s%s' % (self.host, self.path))
                content_file = content_file.replace(
                    '/', sep).replace(':',sep).replace(' ','_')
            else:
                content_file = ('-' +
                   urllib.unquote(self.path.split('/')[-1]).replace(' ','_'))

            extension = self.options.get('extension')
            if extension and not content_file.endswith(extension):
                content_file = content_file + extension
            if self.options.has_key('temp_dir'):
                while 1:
                    temp = expanduser(self.options['temp_dir'])
                    temp = tempnam(temp)
                    content_file = '%s%s' % (temp, content_file)
                    if not exists(content_file):
                        break
            else:
                content_file = mktemp(content_file,'rw')

            logger.debug('Destination filename will be: %r.', content_file)

            body_f = open(content_file, 'wb')
            shutil.copyfileobj(input_file, body_f)
            self.content_file = content_file
            self.saved = False
            body_f.close()
            input_file.close()

            if self.clean_up:
                try:
                    logger.debug('Cleaning up %r.', input_filename)
                    chmod(input_filename, 0777)
                    remove(input_filename)
                except OSError:
                    logger.exception('Failed to clean up %r.', input_filename)
                    pass # Sometimes we aren't allowed to delete it

        except:
            # for security, always delete the input file even if
            # a fatal error occurs, unless explicitly stated otherwise
            # in the config file
            if getattr(self, 'clean_up', True):
                try:
                    exc, exc_data = sys.exc_info()[:2]
                    if input_filename is not None:
                        remove(input_filename)
                except OSError:
                    # Sometimes we aren't allowed to delete it
                    raise exc, exc_data
            raise


    def __del__(self):
        logger.info("Restedit ends at: %s" % time.asctime(time.localtime()) )


    def cleanContentFile(self):
        if self.clean_up and hasattr(self, 'content_file'):
            # for security we always delete the files by default
            try:
                remove(self.content_file)
                logger.info("Content File cleaned up %r at %s" %
                            (self.content_file,
                             time.asctime(time.localtime())))
                return True
            except OSError:
                if self.tried_cleanup:
                    logger.exception("Failed to clean up %r at %s" %
                                     (self.content_file,
                                      time.asctime(time.localtime())))
                    # Issue logged, but it's already the second try.
                    # So continue.
                    return False
                else:
                    logger.debug(("Failed to clean up %r at %s ; retry in 10 "
                                  "sec") % (self.content_file,
                                            time.asctime(time.localtime())))
                    # Some editors close first and save the file ; this may
                    # last few seconds
                    time.sleep(10)
                    self.tried_cleanup = True
                    # This is the first try. It may be an editor issue. Let's
                    # retry later.
                    return self.cleanContentFile()


    def getEditorCommand(self):
        """Return the editor command"""
        editor = self.options.get('editor')

        if win32 and editor is None:
            from _winreg import HKEY_CLASSES_ROOT, OpenKeyEx, \
                                QueryValueEx, EnumKey
            from win32api import FindExecutable, ExpandEnvironmentStrings

            # Find editor application based on mime type and extension
            content_type = self.metadata.get('content_type')
            extension = self.options.get('extension')

            logger.debug('Have content type: %r, extension: %r',
                         content_type, extension)
            if content_type:
                # Search registry for the extension by MIME type
                try:
                    key = 'MIME\\Database\\Content Type\\%s' % content_type
                    key = OpenKeyEx(HKEY_CLASSES_ROOT, key)
                    extension, nil = QueryValueEx(key, 'Extension')
                    logger.debug('Registry has extension %r for '
                                 'content type %r',
                                 extension, content_type)
                except EnvironmentError:
                    pass

            if extension is None:
                url = self.metadata['url']
                dot = url.rfind('.')

                if dot != -1 and dot > url.rfind('/'):
                    extension = url[dot:]
                    logger.debug('Extracted extension from url: %r',
                                 extension)
            classname = editor = None
            if extension is not None:
                try:
                    key = OpenKeyEx(HKEY_CLASSES_ROOT, extension)
                    classname, nil = QueryValueEx(key, None)
                    logger.debug('ClassName for extension %r is: %r',
                                 extension, classname)
                except EnvironmentError:
                    classname = None

            if classname is not None:
                try:
                    # Look for Edit action in registry
                    key = OpenKeyEx(HKEY_CLASSES_ROOT,
                                    classname+'\\Shell\\Edit\\Command')
                    editor, nil = QueryValueEx(key, None)
                    logger.debug('Edit action for %r is: %r',
                                 classname, editor)
                except EnvironmentError:
                    pass

            if classname is not None and editor is None:
                logger.debug('Could not find Edit action for %r. '
                             'Brute-force enumeration.', classname)
                # Enumerate the actions looking for one
                # starting with 'Edit'
                try:
                    key = OpenKeyEx(HKEY_CLASSES_ROOT,
                                    classname+'\\Shell')
                    index = 0
                    while True:
                        try:
                            subkey = EnumKey(key, index)
                            index += 1
                            if str(subkey).lower().startswith('edit'):
                                subkey = OpenKeyEx(key, subkey + '\\Command')
                                editor, nil = QueryValueEx(subkey,
                                                           None)
                            if editor is None:
                                continue
                            logger.debug('Found action %r for %r. '
                                         'Command will be: %r',
                                         subkey, classname, editor)
                        except EnvironmentError:
                            break
                except EnvironmentError:
                    pass

            if classname is not None and editor is None:
                try:
                    # Look for Open action in registry
                    key = OpenKeyEx(HKEY_CLASSES_ROOT,
                                    classname+'\\Shell\\Open\\Command')
                    editor, nil = QueryValueEx(key, None)
                    logger.debug('Open action for %r has command: %r. ',
                                 classname, editor)
                except EnvironmentError:
                    pass

            if editor is None:
                try:
                    nil, editor = FindExecutable(self.content_file, '')
                    logger.debug('Executable for %r is: %r. ',
                                 self.content_file, editor)
                except pywintypes.error:
                    pass

            # Don't use IE as an "editor"
            if editor is not None and editor.find('\\iexplore.exe') != -1:
                logger.debug('Found iexplore.exe. Skipping.')
                editor = None

            if editor is not None:
                return ExpandEnvironmentStrings(editor)

        if editor is None:
            fatalError('No editor was found for that object.\n'
                       'Specify an editor in the configuration file:\n'
                       '(%s)' % self.config.path)

        return editor


    def launch(self):
        """Launch external editor"""

        self.last_mtime = getmtime(self.content_file)
        self.initial_mtime = self.last_mtime
        self.last_saved_mtime = self.last_mtime
        self.dirty_file = False

        command = self.getEditorCommand()

        # Extract the executable name from the command
        if win32:
            if command.find('\\') != -1:
                bin = re.search(r'\\([^\.\\]+)\.exe', command.lower())
                if bin is not None:
                    bin = bin.group(1)
            else:
                bin = command.lower().strip()
        else:
            bin = command

        logger.info('Command %r, will use %r', command, bin)

        if bin is not None:
            # Try to load the plugin for this editor
            try:
                module = 'Plugins.%s' % bin
                Plugin = __import__(module, globals(), locals(),
                                    ('EditorProcess',))
                self.editor = Plugin.EditorProcess(self.content_file)
                logger.info('Launching Plugin %r with: %r',
                             Plugin, self.content_file)
            except (ImportError, AttributeError):
                bin = None

        if bin is None:
            logger.info("No plugin found ; using standard editor process")
            # Use the standard EditorProcess class for this editor
            if win32:
                file_insert = '%1'
            else:
                file_insert = '$1'

            if command.find(file_insert) > -1:
                command = command.replace(file_insert, self.content_file)
            else:
                command = '%s %s' % (command, self.content_file)

            logger.info('Launching EditorProcess with: %r', command)
            self.editor = EditorProcess(command, self.content_file,
                                        self.max_is_alive_counter,
                                        self.lock_file_schemes)
            logger.info("Editor launched successfully")

        launch_success = self.editor.is_alive()

        self.monitorFile()

        if not launch_success:
            fatalError('Editor did not launch properly.\n'
                       'External editor lost connection '
                       'to editor process.\n'
                       '(%s)' % command, exit=False)

        # Check if a file has been modified but not saved back to the CMS
        if self.dirty_file:
            msg = "%s " %(self.title)
            msg += "Some modifications are NOT SAVED to the server.\n "
            if self.last_saved_mtime != self.initial_mtime:
                msg += ("\n This file has been saved at : %s \n" %
                        time.ctime(self.last_saved_mtime))
            else:
                msg += "\n This file has never been saved\n\n "
            msg += "You may have network issues\n\n "
            msg += "Reopen local copy?\n "
            msg += "\n "
            msg += "If you choose 'No',\n "
            msg += "you will loose all your subsequent work.\n "
            msg += "if you choose 'Yes', backup your file."
            if askYesNo(msg):
                logger.exception("File NOT saved ; user decided to re-open a "
                                 "local copy.")
                self.editor.startEditor()

        # Clean content file
        if self.dirty_file:
            logger.exception("Some modifications are NOT saved - ask user "
                             "wether to keep it or not")
            msg = "%s " %(self.title)
            msg += "Local working copy : %s \n " %(self.content_file)
            msg += "Your intranet file hasn't been saved\n "
            msg += "Do you want to keep your logs and temporary working copy ?"
            if askYesNo(msg):
                self.clean_up = False
                self.keep_log = True
                logger.exception("User decides to keep logs and temporary "
                                 "working copy")

        self.cleanContentFile()


    def monitorFile(self):
        final_loop = 0

        while True:
            if not final_loop:
                self.editor.wait(self.save_interval)
            mtime = getmtime(self.content_file)

            if mtime != self.last_mtime:
                logger.debug("File is dirty : changes detected !")
                self.dirty_file = True
                launch_success = True

                self.saved = self.put_changes()
                self.last_mtime = mtime
                if self.saved:
                    self.last_saved_mtime = mtime
                    self.dirty_file = False

            if not self.editor.is_alive():

                if final_loop:
                    logger.info("Final loop done; break")
                    break
                else:
                    # Check wether a file hasn't been saved before closing
                    if mtime != self.last_saved_mtime:
                        self.dirty_file = True
                        launch_success = True
                        self.saved = self.put_changes()
                        self.last_mtime = mtime
                        if self.saved:
                            self.last_saved_mtime = mtime
                            self.dirty_file = False
                    # Go through the loop one final time for good measure.
                    # Our editor's is_alive method may itself *block* during a
                    # save operation (seen in COM calls, which seem to
                    # respond asynchronously until they don't) and subsequently
                    # return false, but the editor may have actually saved the
                    # file to disk while the call blocked.  We want to catch
                    # any changes that happened during a blocking is_alive
                    # call.
                    final_loop = 1
                    logger.info("Final loop")


    def get_opener(self):
        # The opener is yet build ?
        if self.opener is not None:
            return self.opener

        # Build a new opener
        opener = build_opener()
        headers = [ ('User-agent', 'restedit/%s' % __version__) ]

        # An authentication ?
        auth_header = self.metadata.get('auth')
        if auth_header is not None:
            if auth_header.lower().startswith('basic'):
                cls_handler = HTTPBasicAuthHandler
                chal = auth_header[6:].strip()
                # Automatically find the username and the password
                username, password = decode_base64(chal).split(':', 1)
            elif auth_header.lower().startswith('digest'):
                cls_handler = HTTPDigestAuthHandler
                # Automatically find the username, but we must ask the password
                # XXX undocumented functions
                chal = parse_keqv_list(parse_http_list(auth_header[7:]))
                username = chal['username']
                password = askPassword(chal['realm'], username)
            else:
                raise NotImplemented

            password_mgr = HTTPPasswordMgrWithDefaultRealm()
            password_mgr.add_password(realm=None,
                                      uri=self.url,
                                      user=username,
                                      passwd=password)

            auth_handler = cls_handler(password_mgr)
            opener.add_handler(auth_handler)

        # A cookie ?
        if self.metadata.get('cookie'):
            headers.append( ('Cookie', self.metadata['cookie']) )

        # All OK
        opener.addheaders = headers
        self.opener = opener
        return opener


    def send_body(self, body, headers):
        """Send a request back to the CMS"""

        # Get the opener
        opener = self.get_opener()

        # Make a new request
        request = Request(self.url, data=body)
        # XXX Bad (or not) hack to make a PUT instead of a POST
        request.get_method = lambda : 'PUT'

        # Add the additional headers
        for key, value in headers.iteritems():
            request.add_header(key, value)

        # Try to connect
        try:
            return opener.open(request)
        except HTTPError:
            return None


    def put_changes(self):
        """Save changes to the file back to the CMS"""
        logger.info("put_changes at: %s" % time.asctime(time.localtime()))

        # Read the new body
        body = open(self.content_file, 'rb')
        body = body.read()
        logger.info("Document is %s bytes long" % len(body) )

        # Send with the header "If-Unmodified-Since"
        headers = {'Content-Type': self.metadata.get('content_type',
                                                     'text/plain'),
                   'If-Unmodified-Since': datetime_to_http_date(
                                                self.last_modified) }
        response = self.send_body(body, headers)

        # Don't keep the body around longer then we need to
        del body

        # An error ?
        if response is not None and response.code / 100 != 2:
            if askRetryAfterError(response, 'Could not transfer the changes\n'
                                            'Error occurred during HTTP put'):
                return self.put_changes()
            else:
                logger.error('Could not transfer the changes\n'
                             'Error occurred during HTTP PUT')
                return False

        # Get the new Last-Modified
        last_modified = response.headers.get('Last-Modified')
        self.last_modified = http_date_to_datetime(last_modified)

        # All OK
        logger.info("File successfully saved back to the intranet")
        return True


    def edit_config(self):
        logger.info('Edit local configuration')

	# The good path, ...
        if win32:
            config_path = expanduser('~\\Restedit.ini')
        else:
            config_path = expanduser('~/.resteditrc')

	# Yet a file ?
	if exists(config_path):
            if askYesNo("Do you want to replace your configuration file "
                        "with the default one ?"):
                logger.info("Replace the configuration file with the default "
                            "one.")
                config_file = open(config_path, 'w')
                config_file.write(get_default_configuration())
                config_file.close()

	# Launch an editor
	if win32:
	    startfile(config_path)
	else:
            # Launch default editor with the user configuration file
            default_editor = Configuration().config.get('general',
			    				'config_editor',
                                                        '')
            if not default_editor:
                logger.critical(
			"No default editor. Configuration edition failed.")
                sys.exit(0)
            logger.info("Edit configuration file %s with editor %s" %
                        (config_path, default_editor))
            os.system("%s %s" % (default_editor, config_path))



def askRetryAfterError(response, operation, message=''):
    """Dumps response data"""
    if not message \
       and response.getheader('Bobo-Exception-Type') is not None:
        message = '%s: %s' % (response.getheader('Bobo-Exception-Type'),
                              response.getheader('Bobo-Exception-Value'))
    return askRetryCancel('%s:\n%d %s\n%s' % (operation, response.status,
                                           response.reason, message))



class EditorProcess:

    def __init__(self, command, contentfile, max_is_alive_counter,
                 lock_file_schemes):
        """Launch editor process"""

        self.command = command
        self.contentfile = contentfile
        self.lock_file_schemes = lock_file_schemes

        # is_alive variables
        self.is_alive_counter = 0
        self.max_is_alive_counter = max_is_alive_counter
        self.lock_detected = False
        self.start_sequence = True

        # Methods to use with is_alive
        self.selected_method = -1
        if win32:
            self.methods = [ self.test_lock_file,
                             self.test_file_open_win32,
                             self.test_PID_win32 ]
        else:
            self.methods = [ self.test_lock_file,
                             self.test_file_open_unix,
                             self.test_PID_unix ]

        # Go
        if win32:
            self.start_editor_win32()
        else:
            self.start_editor_unix()


    def start_editor_win32(self):
        try:
            logger.debug('CreateProcess: %r', self.command)
            self.handle, nil, nil, nil = CreateProcess(None, self.command,
                                                       None, None, 1, 0, None,
                                                       None, STARTUPINFO())
        except pywintypes.error, e:
            fatalError('Error launching editor process\n'
                       '(%s):\n%s' % (self.command, e[2]))


    def start_editor_unix(self):
        # Prepare the command arguments, we use this regex to
        # split on whitespace and properly handle quoting
        arg_re = r"""\s*([^'"]\S+)\s+|\s*"([^"]+)"\s*|\s*'([^']+)'\s*"""
        args = re.split(arg_re, self.command.strip())
        args = filter(None, args) # Remove empty elements
        self.pid = os.spawnvp(os.P_NOWAIT, args[0], args)


    def wait(self, timeout):
        """Wait for editor to exit or until timeout"""
        sleep(timeout)


    def test_file_open_win32(self):
        """Test the file is locked on the FS"""
        try:
            fileOpen = file(self.contentfile, 'a')
        except IOError, e:
            if e.args[0]==13:
                logger.debug("Document is writeLocked by command")
                self.cmdLocksWrite = True
                return True
            else:
                logger.error( "%s %s " % (e.__class__.__name__, str(e)))
        fileOpen.close()
        logger.info("File is not open : Editor is closed")
        return False


    def test_PID_win32(self):
        """Test PID"""
        if GetExitCodeProcess(self.handle) == 259:
            logger.info("Pid is up : Editor is still running")
            return True
        logger.info("Pid is not up : Editor exited")
        return False


    def test_file_open_unix(self):
        """Test if the file is locked on the FS"""
        logger.debug("test if the file edited is locked by filesystem")
        isFileOpenNum = popen2.Popen4('/bin/fuser %s' %
                                      self.command.split(' ')[-1]).wait()
        return isFileOpenNum == 0


    def test_PID_unix(self):
        """Test PID"""
        try:
            exit_pid, exit_status = os.waitpid(self.pid, os.WNOHANG)
        except OSError:
            return False
        return exit_pid != self.pid


    def test_lock_file(self):
        """Test Lock File"""

        if win32:
            file_separator="\\"
        else:
            file_separator="/"

        original_filepath = self.contentfile.split(file_separator)
        logger.debug("log file schemes : %s" % self.lock_file_schemes)
        for i in self.lock_file_schemes:
            filepath = original_filepath[:]
            if i == '':
                continue
            filepath[-1] = i % filepath[-1]
            filename = file_separator.join(filepath)
            logger.debug("Test: lock file : %s" % filename)
            if glob.glob(filename):
                self.lock_file_schemes = [i]
                return True

        return False


    def is_alive(self):
        """Returns true if the file is yet edited"""

        if self.start_sequence:
            logger.info("is_alive : still starting. Counter : %s" %
                        self.is_alive_counter)
            if self.is_alive_counter < self.max_is_alive_counter :
                self.is_alive_counter += 1
            else:
                self.start_sequence = False

        for i, method in enumerate(self.methods):
            if method():
                logger.debug("is_alive: True ( %s : %s)" % (i, method.__doc__))
                if i != self.selected_method:
                    logger.info("DETECTION METHOD CHANGE: %d - %s" %
                                (i, method.__doc__))
                self.selected_method = i
                self.lock_detected = True
                return True

        logger.info("is_alive: no edition detected.")
        if self.start_sequence and not self.lock_detected:
            logger.debug("is_alive: still in the startup process : continue.")
            return True
        return False



def read_metadata(input_file):
    """Read the metadata from the input_file
    """
    metadata = {}
    while True:
        line = input_file.readline()

        # The end ?
        if line == '\n':
            return metadata

        header_name, header_body = line.split(':', 1)
        metadata[header_name.strip()] = header_body.strip()



def http_date_to_datetime(http_date):
    # RFC 1945
    result = parsedate_tz(http_date)
    result = mktime_tz(result)
    return datetime.fromtimestamp(result)



def datetime_to_http_date(value):
    # RFC 1945
    result = value.timetuple()
    result = mktime(result)
    return formatdate(result, usegmt=True)



# User Input/Ouput
def has_tk():
    """Sets up a suitable tk root window if one has not
       already been setup. Returns true if tk is happy,
       false if tk throws an error (like its not available)"""
    # Create a hidden root window to make Tkinter happy
    if not locals().has_key('tk_root'):
        try:
            global tk_root
            from Tkinter import Tk
            tk_root = Tk()
            tk_root.withdraw()
            return True
        except:
            return False
    return True



def tk_flush():
    tk_root.update()



def askPassword(realm, username):
    """Password dialog box"""
    if has_tk():
        from tkSimpleDialog import askstring
        pwd = askstring(TK_TITLE,
                        "Please enter the password for '%s' in '%s'" %
                        (username, realm), show='*')
        tk_flush()
        return pwd



def errorDialog(message):
    """Error dialog box"""
    if has_tk():
        from tkMessageBox import showerror
        showerror(TK_TITLE, message)
        tk_flush()
    else:
        print message



def messageDialog(message):
    """Message dialog box"""
    if has_tk():
        from tkMessageBox import showinfo
        showinfo(TK_TITLE, message)
        tk_flush()
    else:
        print message



def askRetryCancel(message):
    if has_tk():
        from tkMessageBox import askretrycancel
        response = askretrycancel(TK_TITLE, message)
        tk_flush()
        return response



def askYesNo(message):
    if has_tk():
        from tkMessageBox import askyesno
        response = askyesno(TK_TITLE, message)
        tk_flush()
        return response


def fatalError(message, exit=True):
    """Show error message and exit"""
    global log_file
    msg = 'FATAL ERROR: %s' % message
    errorDialog(msg)
    # Write out debug info to a temp file
    # traceback_filename = mktemp(suffix='-restedit-traceback.txt')
    if log_file is None:
        log_file = mktemp(suffix='-restedit-traceback.txt')
    debug_f = open(log_file, 'a+b')
    try:
        # Copy the log_file before it goes away on a fatalError.
        #if log_file is not None:
        #    log_file.seek(0)
        #    shutil.copyfileobj(log_file, debug_f)
        #    print >> debug_f, '-' * 80
        traceback.print_exc(file=debug_f)

    finally:
        debug_f.close()
    if exit:
        sys.exit(0)



default_configuration = """# The RESTful editor (restedit) configuration

[general]
# General configuration options
version = {version}

# Temporary file cleanup. Set to false for debugging or
# to waste disk space. Note: setting this to false is a
# security risk to the CMS server
# cleanup_files = 1
# keep_log = 1

# Max is_alive counter
# This is used in order to wait the editor to effectively lock the file
# This is the number of 'probing' cycles
# default value is 5 cycles of save_interval

# Automatic save interval, in seconds. Set to zero for
# no auto save (save to the CMS only on exit).
# save_interval = 5 max_isalive_counter = 5

# Lock File Scheme
# These are schemes that are used in order to detect "lock" files
# %%s is the edited file's name (add a ';' between each scheme):
# lock_file_schemes=.~lock.%%s#;~%%s.lock
lock_file_schemes=.~lock.%%s#;.%%s.swp

# Uncomment and specify an editor value to override the editor
# specified in the environment
config_editor = {default_editor}

# Default editor
editor = {default_editor}

# log level : default is 'info'.
# It can be set to debug, info, warning, error or critical.
# log_level = debug

# If your server is not using utf-8
# server_charset = utf-8

# If your client charset is not iso-8859-1
# client_charset = iso-8859-1

# Specific settings by content-type. Specific
# settings override general options above.

[content-type:text/plain]
extension=.txt

[content-type:text/html]
extension=.html

[content-type:text/xml]
extension=.xml

[content-type:text/css]
extension=.css

[content-type:text/javascript]
extension=.js

[general-type:image/*]
editor=gimp -n

[content-type:application/x-xcf]
editor=gimp -n

[content-type:application/vnd.oasis.opendocument.text]
extension=.odt
editor={openOffice}

[content-type:application/vnd.sun.xml.writer]
extension=.sxw
editor={openOffice}

[content-type:application/vnd.sun.xml.calc]
extension=.sxc
editor={openOffice}

[content-type:application/vnd.oasis.opendocument.spreadsheet]
extension=.ods
editor={openOffice}

[content-type:application/vnd.oasis.opendocument.presentation]
extension=.odp
editor={openOffice}

[content-type:application/msword]
extension=.doc
editor={openOffice}

[content-type:application/vnd.ms-excel]
extension=.xls
editor={openOffice}

[content-type:application/vnd.ms-powerpoint]
extension=.ppt
editor={openOffice}
"""
def get_default_configuration():
    if win32:
        default_editor = 'notepad'

	# Try to find automatically OpenOffice
	try:
	    key = OpenKey(HKEY_LOCAL_MACHINE,
	                  'SOFTWARE\\OpenOffice.org\\OpenOffice.org')
	    version = EnumKey(key, 0)
	    key = OpenKey(HKEY_LOCAL_MACHINE,
	                  'SOFTWARE\\OpenOffice.org\\OpenOffice.org\\' +
			  version)
	    openOffice = QueryValueEx(key, 'Path')[0]
	except WindowsError:
	    openOffice = 'soffice'

    else:
        default_editor = 'gvim -f'
        openOffice = 'soffice'

    return default_configuration.format(version=__version__,
		                        default_editor=default_editor,
					openOffice=openOffice)



if __name__ == '__main__':

    # Options initialisation
    usage = '%prog <file>'
    description = 'RESTful External Editor'
    parser = OptionParser(usage, version=__version__, description=description)

    # Parse !
    _, args = parser.parse_args()

    # Input file
    if len(args) == 0:
        input_filename = None
    elif len(args) == 1:
        input_filename = args[0]
    else:
        parser.print_help()
        sys.exit(1)

    # Go
    try:
        ExternalEditor(input_filename).launch()
    except (KeyboardInterrupt, SystemExit):
        pass
    except:
        fatalError(sys.exc_info()[1])
