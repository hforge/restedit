This is the RESTful editor, an utility to edit content in a CMS with
your desktop applications (e.g. Gimp, OpenOffice, vim, etc.)

An optimistic restful [1] mechanism based in timestamps is used to talk
with the server.  This mechanism uses HTTP/1.1, in particular the PUT
method and the If-Unmodified-Since header.  At least the Ikaaro [2] CMS
is known to support this mechanism and to work with restedit.

This software is a fork of zopeedit [3], the main difference is the
mechanism used to talk with the server (restful or not restful).

[1] http://en.wikipedia.org/wiki/Representational_State_Transfer
[2] http://www.hforge.org/ikaaro
[3] http://plone.org/products/zope-externaleditor-client


Install
-------

Python 2.5 or later is required.  Python 3 is not yet supported.

The RESTful editor is a single file, restedit.py, just copy this file
to some folder.  For instance:

  # cp restedit.py /usr/local/bin/

Then configure your browser so it will use the restedit.py script to
open web pages with the 'application/x-restedit' mimetype.

The first time the script is run it will create a '.resteditrc' file in
your home directory.  Edit this file to customize restedit: for example
you can choose which applications to use to edit different file types.


Resources
---------

Download
http://download.hforge.org/restedit/1.0/restedit-1.0.0.tar.gz

Home
http://www.hforge.org/restedit/

Mailing list
http://www.hforge.org/community/
http://archives.hforge.org/index.cgi?list=itools

Bug Tracker
http://bugs.hforge.org/


Copyright notice
----------------

Copyright (c) 2001, 2002 Zope Corporation and Contributors.
Copyright (c) 2010 David Versmisse <david.versmisse@itaapy.com>
All Rights Reserved.

This software is subject to the provisions of the Zope Public License,
Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
FOR A PARTICULAR PURPOSE.
