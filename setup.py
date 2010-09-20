from distutils.core import setup
from platform import architecture
from shutil import copyfile
import py2exe

# Make the dist directory 
setup(windows=['restedit.py'])

# Copy the good vcredist file
if architecture()[0].startswith('32'):
    copyfile('vcredist_x86.exe', 'dist/vcredist_x86.exe')
else:
    copyfile('vcredist_x64.exe', 'dist/vcredist_x64.exe')


