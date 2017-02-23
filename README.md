# TDSAnomalPE

## Summary
The script utilizes python's pefile module to parse TimeDateStamp data points in a file header. TDSAnomalPE (TimeDateStamp plus a bad pun) compares identified data points to the compile time stored in the PE header. If there are discrepancies  between them, it identifies them as possible evidence of compile time manipulation. TDSAnomalPE also compares the checksum in the header to a calculated checksum to see if they match, since mismatched checksums could indicate header manipulation. 

For more information on the methodology behind this script, visit [missmalware.com](http://missmalware.com/).

## Documentation and Use
Download the script and run it using Python.

To run the script from the command line and print the results: ``` python TDSAnomalPE.py [file path] ``` 

To run the script from a basic GUI: ``` python TDSAnomalPE.py ```
