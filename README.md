# CVE2Table

CVE2Table will take a list of CVEs, search for additional information and return a markdown table. The purpose of this project is to provide a simple and easy to use markdown table generator for pentest reports and similar stuff. The tool will search for all CVEs using the CIRCL.lu REST-API. 

## Installation

...

## Usage

This command will search for all CVEs in test.data. The result will be stored in anotherfilename.md and without the field summary.
```
CVE2Table -f .\test.data -t C:\some\path\to\store\the\markdown\file -to anotherfilename.md -nosum
```

This command will search for all CVEs in test.data. The result will be stored in anotherfilename.md.
```
CVE2Table -f .\test.data -t C:\some\path\to\store\the\markdown\file -to anotherfilename.md
```