# HoN-Guide-Pcap-Scraper

A simple utility to extract HoN guide data from pcap captures.

## Repository structure

- `hon_pcap_guide_parser.py` - The main utility
- `/curated json/` - Folder containing pre-curated json from guides.

## How to run

Execute the script using the following syntax:

```
python hon_pcap_guide_parser --pcaps <files> --output <output_name>
```

The following arguments are supported:

- `--pcaps` - the pcap file(s) to parse
- `--output` - the output json file name
- (Optional) `--author_filter` - Specify a guide author to filter by.
- (Optional) `--hero_filter` - Specify a hero name to filter by.
- (Optional) `--dry_run` - prints the final output instead of saving to a file