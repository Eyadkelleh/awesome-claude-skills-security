=================================
Most common passwords for Iceland
=================================

.. contents:: Table of Contents

Description
-----------

TLDR: This is a tentative list of most common passwords used by Iceland residents.
This readme describes the extraction process.
If you are just interested in the lists proper, look in the repo.

**NB: more files may be added a later time, watch this repo to be notified of future changes.**

Files available
---------------

The following lists are provided:

- most-common-passwords.csv: derived from the "Breach compilation" dump - see below for details
- vodafone.csv: In November 2013, Vodafone Iceland experienced a data breach attributed to the Turkish hacker group Maxn3y - see below for details

Vodafone Iceland
----------------

Methodology
~~~~~~~~~~~

The file vodafone.csv is derived from the "signup" Mysql table after filtering of null passwords etc.

Known caveats:

- Some users are registered in different names, so their password is repeated more than once but actually represents a unique occurrence
- Probable pollution: SHA256 hashes

References
~~~~~~~~~~

Further details about leaked files:

- `Vodagate – vefur Vodafone á íslandi hakkaður <https://www.lappari.com/2013/11/vodagate-vefur-vodafone-a-islandi-hakkadur/>`_


"Breach compilation"
--------------------

Methodology
~~~~~~~~~~~

Use the "Breach compilation" data dump amd filter passwords associated with an E-mail address ending in .is.

Steps to reproduce
~~~~~~~~~~~~~~~~~~

Get the dump
############

Obtain the "Breach compilation" data dump. As of writing this, the magnet link below is still active:

.. code::

   magnet:?xt=urn:btih:7ffbcd8cee06aba2ce6561688cf68ce2addca0a3&dn=BreachCompilation&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A80&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969&tr=udp%3A%2F%2Fglotorrents.pw%3A6969&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337

Result: 74041 lines

Filtering
#########

Extract lines that contain an E-mail address ending in .is.

.. code:: bash

   grep --no-filename -ir "\.is:" * | tee breached-is-addresses.csv

Clean up
########

A small number of malformed lines have more than two fields, so we just discard them.

.. code:: bash

   awk  'FS=":" { if (NF == 2) { print $0} }' breached-is-addresses.csv > breached-is-addresses.cleaned.csv

Count and sort passwords by frequency
#####################################

You can use the Python script below to read the cleaned csv file and write back results to another file in CSV format.

.. code:: python

    import csv
    from collections import Counter
    
    # fill out below
    source_file = "/tmp/breached-is-addresses.cleaned.csv"
    output_file = "/tmp/most-common-passwords.csv"
    
    
    def read_csv_file(filename, delimiter=",", fieldnames=("email", "password")):
        with open(filename, "r", newline="") as f:
            reader = csv.DictReader(f, delimiter=delimiter, fieldnames=fieldnames)
            for row in reader:
                yield row
    
    
    def write_csv_file(filename, rows, delimiter=",", fieldnames=("password", "count")):
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f, delimiter=delimiter)
            writer.writerow(fieldnames)
            for row in rows:
                writer.writerow(row)
    
    
    password_counter = Counter(
        row["password"] for row in read_csv_file(filename=source_file, delimiter=":")
    )
    
    sorted_counter = sorted(password_counter.items(), key=lambda i: i[1], reverse=True)
    write_csv_file(filename=output_file, rows=sorted_counter, delimiter=",")
    
    