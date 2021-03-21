"""
What is this register used for?
Hmm.. I'll just rename it to veryuniquename, do a textual search, and find all references!
Ok.. Waiting for the search to end.. any minute now.. Done!
Now I just need to understand which of the search result is relevant to the current usage frame of the register.
Shouldn't be too hard, right?
"""

If this happened to you (perhaps more than once), you are in for a treat!
Just Shift-X, and your troubles will go away!

You may also re(g)name the register in the usage frame. Just Shift-N, and follow instructions!
And a new addition may also make all references in the functions know their type. Just Shift-T it!

=== Installation ===
This plugin needs sark. Get it.
After that, use sark's plugins.list file (a sark way of adding plugins - needs to be installed directly, not through pip install sark), 
and add a line containing:
FULLPATH\oregami\oregami_window.py
FULLPATH\oregami\regname_plugin.py
FULLPATH\oregami\typeregter_plugin.py


Alternatively:
Copy all files (including internal folder) to the IDA plugins directory.


