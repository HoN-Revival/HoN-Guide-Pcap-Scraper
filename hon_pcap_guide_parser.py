import argparse
import json
import re
import sys

from collections import OrderedDict
from phpserialize import unserialize
from scapy.all import *


def parse_pcap_file(pcap_path, author_filter=None, hero_filter=None):
    spans_multiple_packets = False
    running_content = ''
    guides = {}
    for packet in PcapReader(pcap_path):
      try:
        if packet[TCP].sport != 80:  # HTTP response
          continue
        payload_text = packet[TCP].payload.load.decode("utf-8")
        payload = ''
        if not spans_multiple_packets and not 'guide_name' in payload_text:
          continue
        if spans_multiple_packets:
          payload = running_content + payload_text
          spans_multiple_packets = False
          running_content = ''
        else:
          payload_segments = payload_text.split('\r\n\r\n')
          header = payload_segments[0]
          payload = payload_segments[1]
          match = re.search('Content-Length: (\d+)', header, re.IGNORECASE)
          length = int(match.group(1))
          if len(payload) < length:
            spans_multiple_packets = True
            running_content = payload
            continue
        deserialized_payload = unserialize(payload.encode(), decode_strings=True)
        if author_filter and deserialized_payload["author_name"] != author_filter:
          continue
        if hero_filter and deserialized_payload["hero_name"].lower() != hero_filter.lower():
          continue
        hero_name = deserialized_payload['hero_cli_name']
        hero_guides = guides.get(hero_name, [])
        hero_guides.append(deserialized_payload)
        guides[hero_name] = hero_guides
      except Exception as e:
        pass
    return guides


def main(args):
  all_guides = {}
  for file_path in args.pcaps:
    if not file_path.endswith('.pcap'):
      print(f'Skipping invalid input file: {file_path}. Input file is not a .pcap file.')
      continue
    print(f'Parsing file: {file_path}')
    guides = parse_pcap_file(file_path, args.author_filter, args.hero_filter)
    all_guides.update(guides)
  sorted_guides = OrderedDict(sorted(all_guides.items()))
  json_dump = json.dumps(
      sorted_guides,
      indent=4,
      separators=(',', ': ')
  )
  if args.dry_run:
    print(json_dump)
    return
  with open(args.output, 'w') as f:
    f.write(json_dump)
    

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description = 'Extract HoN guides from pcap files')
  parser.add_argument('--pcaps', nargs='+', help='The path to the pcap file(s) to parse.', required=True)
  parser.add_argument('--output', help='The path to the output where the json file should be written.', required=True)
  parser.add_argument('--author_filter', help='An optional filter to only parse guides by a specific author.')
  parser.add_argument('--hero_filter', help='An optional filter to only parse guides matching a given hero name.')
  parser.add_argument('--dry_run', action='store_true', help='Prints the json instead of saving it to a file.')
  args = parser.parse_args()
  main(args)