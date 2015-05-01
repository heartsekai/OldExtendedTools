# make a module from .ps1
# http://www.kmerwin.com/?p=174

gci $psscriptroot\*.ps1 -Recurse | % {. $_.FullName }