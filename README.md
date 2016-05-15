Analyzes all DMARC reporting .xml files in the current directory and all
subdirectories. Prints the result as a formatted Unicode table with ANSI
coloring.

The coloring tries to reflect the interpretation. Own IP addresses are
printed green, other ones yellow, and the disposition, DKIM and SPF columsn
are colored red or green depending on whether the code decides the action
taken by the server was 'good'. If you don't like this coloring, feel free
to adjust the code.

Before running, edit `analysis.py` and set `OWN_IPS` to the set of acceptable
sending IPs for your mail server.
