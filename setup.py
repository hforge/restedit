from distutils.core import setup
import py2exe

setup(data_files=["msvcr90.dll"],
      windows=['restedit.py'])

