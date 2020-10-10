DMARC Report Analyzer
=====================

Analyzes all DMARC reporting .xml files in the current directory and all
subdirectories. Prints the result as a formatted Unicode table with ANSI
coloring.

The coloring tries to reflect the interpretation. Own IP addresses are
printed green, other ones yellow, and the disposition, DKIM and SPF columns
are colored red or green depending on whether the code decides the action
taken by the server was 'good'. If you don't like this coloring, feel free
to adjust the code.

Before running, you need to set up `config.yaml` and - if you want to use
IMAP fetching - `config.sops.yaml`. The `config.sops.yaml` file must be
encrypted with [Mozilla SOPS](https://github.com/mozilla/sops).

The utility `fetch.py` allows to fetch DMARC reports from an IMAP account,
and `extract.py` allows to batch extract compressed DMARC reports.

Configuration
-------------

`config.yaml` can have the following keys:

* `own_ips`: dictionary mapping an IP address to a dictionary. The inner dictionary
  can contain fields `from` and `until` to specify from when until when the address
  was valid. Omitting `from` means the IP address has been valid until `until`, and
  omitting `until` means the IP address is valid from `from` on. Omitting both means
  the IP address is always valid.
* `identify_own_ips_from_dkim_and_spf`: instead of providing an explicit set of IP
  addresses in `own_ips`, you can also set `identify_own_ips_from_dkim_and_spf` to
  `true` to accept the IP addresses as correct where both DKIM and SPF policies
  evaluate to `pass`. Only used by `analysis.py`.
* `imap_server`: the IMAP server address for fetching DMARC reports from. Only used
  by `fetch.py`.
* `imap_folder`: the IMAP folder name for fetching DMARC reports from. Only used by
  `fetch.py`.
* `imap_user`: the IMAP user name for fetching DMARC reports from. Only used by
  `fetch.py`.

`config.sops.yaml` can have the following keys:

* `imap_password`: the IMAP user name for fetching DMARC reports from. Only used by
  `fetch.py`.

Workflow
--------

After setting up `config.yaml` and `config.sops.yaml` (optional), you can do the
following:

1. (Optional) Run `fetch.py` to fetch DMARC reports from IMAP. The attachments are
   extracted into the current directory and the mails marked as read. Only unread
   emails are processed.
2. Run `extract.py` to extract DMARC reports into the subdirectory `files/`.
3. Run `analysis.py` to print an analysis of the reports. See `analysis.py --help`
   for information on command line options.

License
-------

The tools are licensed under the MIT license. See [LICENSE](./LICENSE) for details.
