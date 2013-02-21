#! /usr/bin/python
# by pts@fazekas.hu at Sat Mar 24 17:32:25 CET 2012
#
# mmshget: mmsh:// (MMS-over-HTTP) video stream downloader and reference
# implementation
#
# mmshget is a Python script to download streaming videos of the mmsh://
# (MMS-over-HTTP) protocol, in .wmv (or .asf) format. mmshget can also be
# used as an easy-to-understand, simple, client-side, partial reference
# implementation of the mmsh:// protocol. mmshget works with Python 2.4,
# 2.5, 2.6 and 2.7.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
#
# Use this script to download .wmv (.asf) files from mmsh:// URLs. This
# implementation doesn't have sophisticated error handling (just asserts) or
# recovery. This implementation is simple enough to be a reference
# implementation for the client-side of the mmsh:// protocol in Python.
# This implementation is inspired by mmsh.c in libmms-0.4.
#
# TODO(pts): Add continuation of a previously aborted download.

__author__ = 'pts@fazekas.hu (Peter Szabo)'

import array
import os
import re
import socket
import struct
import sys
import time


def ShellQuote(string):
  # TODO(pts): Make it work properly on non-Unix systems.
  string = str(string)
  if string and not re.search('[^-_.+,:/a-zA-Z0-9]', string):
    return string
  elif sys.platform.startswith('win'):
    # TODO(pts): Does this replace make sense?
    return '"%s"' % string.replace('"', '""') 
  else:
    return "'%s'" % string.replace("'", "'\\''")

                                        
# --- Proxy

HTTP_PROXY_RE = re.compile(r'(?:\w+://)?([^+%@?#:/]+)(?::(\d+))?(?:/|\Z)')

def GetProxyForHost(host):
  """Returns None or (proxy_host, proxy_port)."""
  http_proxy = os.getenv('http_proxy', '')
  if not http_proxy:
    return None
  for item in os.getenv('no_proxy', '').split(','):
    if item:
      if item.starswith('.'):
        if host.endswith(item):
          return None
      else:
        if host == item:
          return None
  match = HTTP_PROXY_RE.match(http_proxy)
  assert match, 'Bad http_proxy=%r' % http_proxy
  proxy_host = match.group(1)
  if match.group(1) is None:
    proxy_port = 80
  else:
    proxy_port = int(match.group(2))
  assert 1 <= proxy_port <= 65535, 'Bad proxy_port=%d, http_proxy=%r' % (
      proxy_port, http_proxy)
  return (proxy_host, proxy_port)

URL_RE = re.compile(r'(?:http|mmsh)://([^+%@?#:/]+)(?::(\d+))?(/[^\s#]*)?\Z')
"""This is the URL subset syntax we support."""

RESPONSE_LINE1_RE = re.compile(
    r'HTTP/(1[.][01]) +(\d{3}) +(\S[^\r\n]*)\r?\n\Z')
RESPONSE_HEADER_RE = re.compile(r'([A-Za-z][-\w]*): ?([^\r\n]*)\Z')


def DoHttpRequest(url, request_headers=(), timeout=30, post_data=None,
                  content_length_out=None):
  """Send a HTTP GET request.

  DoHttpRequest(url) is similar to urllib.urlopen(url).

  Args:
    url: String containing an http:// or mmsh:// URL.
    request_headers: Sequence of strings containing request headers to send.
    timeout: Timeout for each socket operation, in seconds.
    content_length_out: To-be-appended list for Content-Length or None.
  Returns:
    Returns a file-like object for reading the response body.
  """
  # Not using `import urllib', because that doesn't support proxies.
  match = URL_RE.match(url)
  assert match, 'Bad url=%r' % (url,)
  host = match.group(1)
  if match.group(2) is None:
    port = 80
  else:
    port = int(match.group(2))
  assert 1 <= port <= 65535, 'Bad request port=%d, url=%r' % (port, url)
  path = match.group(3) or '/'
  if port == 80:
    hostport = host
  else:
    hostport = '%s:%s' % (host, port)
  if post_data is None:
    method = 'GET'
  else:
    method = 'POST'

  proxy_address = GetProxyForHost(host)
  if proxy_address:
    connect_address = proxy_address
    req = ['%s http://%s%s HTTP/1.0\r\nHost: %s\r\n' %
           (method, hostport, path, hostport)]
  else:
    connect_address = (host, port)
    req = ['%s %s HTTP/1.0\r\nHost: %s\r\n' % (method, path, hostport)]
  for header in request_headers:
    header = header.rstrip('\r\n')
    if header:
      assert ':' in header, 'Missing colon in request_header=%r' % (header,)
      assert '\n' not in header, (
          'Unexpected newline in request_header=%r' % (header,))
      assert '\r' not in header, (
          'Unexpected CR in request_header=%r' % (header,))
      req.append(header + '\r\n')
  if post_data is not None:
    if not isinstance(post_data, str):
       raise TypeError
    # TODO(pts): Check that Content-Type is present in request_headers.
    req.append('Content-Length: %d\r\n' % len(post_data))
  req.append('\r\n')
  if post_data is not None:
    req.append(post_data)
  req = ''.join(req)

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
  sock.settimeout(timeout)
  sock.connect(connect_address)
  sock.sendall(req)
  f = sock.makefile()  # For reading.
  del sock

  line1 = f.readline()
  match = RESPONSE_LINE1_RE.match(line1)
  assert match, 'Bad HTTP response line1=%r' % line1
  response_protocol = match.group(1)
  response_status = int(match.group(2))
  response_message = match.group(2)
  # TODO(pts): Add support for redirects, e.g. from http://www.example.org/
  assert response_status == 200, (
      'HTTP server returned error status=%d message=%r' %
      (response_status, response_message))
  del line1, response_protocol, response_status, response_message

  while True:
    line = f.readline()
    assert line, 'Unexpected EOF in HTTP response headers.'
    line = line.rstrip('\r\n')
    if not line:
      break
    match = RESPONSE_HEADER_RE.match(line)
    assert match, 'Bad HTTP response line=%r' % line
    name = match.group(1).lower()
    value = match.group(2).strip()
    if content_length_out is not None:
      if name == 'content-length':
        content_length_out.append(int(value))

  return f


# --- mmsh:// downloader

CHUNK_TYPE_RESET      = 0x4324
CHUNK_TYPE_DATA       = 0x4424
CHUNK_TYPE_END        = 0x4524
CHUNK_TYPE_ASF_HEADER = 0x4824
EXT_HEADER_SIZES = {
    CHUNK_TYPE_RESET      : 4,
    CHUNK_TYPE_DATA       : 8,
    CHUNK_TYPE_END        : 4,
    CHUNK_TYPE_ASF_HEADER : 8,
}
NAME_FROM_TYPE = {
    CHUNK_TYPE_RESET      : 'RESET',
    CHUNK_TYPE_DATA       : 'DATA',
    CHUNK_TYPE_END        : 'END',
    CHUNK_TYPE_ASF_HEADER : 'ASF_HEADER',
}

ASF_MAX_HEADER_SIZE = 16384
ASF_MAX_NUM_STREAMS = 23

# The binary version of these hex strings appear in the file like this
# verbatim.
GUID_ASF_FILE_PROPERTIES = 'a1dcab8c47a9cf118ee400c00c205365'
GUID_ASF_STREAM_PROPERTIES = '9107dcb7b7a9cf118ee600c00c205365'
GUID_ASF_AUDIO_MEDIA = '409e69f84d5bcf11a8fd00805f5c442b'
GUID_ASF_VIDEO_MEDIA = 'c0ef19bc4d5bcf11a8fd00805f5c442b'
GUID_ASF_COMMAND_MEDIA = 'c0cfda59e659d011a3ac00a0c90348f6'
GUID_ASF_JFIF_MEDIA = '00e11bb64e5bcf11a8fd00805f5c442b'
GUID_ASF_DEGRADABLE_JPEG_MEDIA = 'e07d903515e4cf11a91700805f5c442b'
GUID_ASF_STREAM_BITRATE_PROPERTIES = 'ce75f87b8d46d1118d82006097c9a2b2'
GUID_ASF_DATA = '3626b2758e66cf11a6d900aa0062ce6c'


def ParseAsfHeader(asf_head):
  assert asf_head, 'Missing ASF header.'
  i = 30
  packet_size = 0
  file_size = None
  stream_ids = {}
  stream_bitrates = {}
  stream_bitrates_pos = {}
  packet_count = None
  while i + 24 <= len(asf_head):
    guid, size = struct.unpack('<16sQ', asf_head[i : i + 24])
    size = int(size)
    assert size >= 24
    guid_hex = guid.encode('hex')
    # TODO(pts): Get file size for progress bar etc.
    if guid_hex == GUID_ASF_FILE_PROPERTIES:
      assert size >= 100
      packet_size = int(struct.unpack('<L', asf_head[i + 92 : i + 96])[0])
      assert packet_size > 0
      assert packet_size <= 65536, 'Too large packet_size=%d' % packet_size
      file_size = int(struct.unpack('<Q', asf_head[i + 40 : i + 48])[0])
    elif guid_hex == GUID_ASF_STREAM_PROPERTIES:
      assert size >= 74
      stream_type_guid_hex = asf_head[i + 24 : i + 40].encode('hex')
      if stream_type_guid_hex == GUID_ASF_AUDIO_MEDIA:
        stream_type = 'audio'
      elif stream_type_guid_hex in (GUID_ASF_VIDEO_MEDIA,
                                    GUID_ASF_JFIF_MEDIA,
                                    GUID_ASF_DEGRADABLE_JPEG_MEDIA):
        stream_type = 'video'
      elif stream_type_guid_hex == GUID_ASF_COMMAND_MEDIA:
        stream_type = 'command'
      else:
        stream_type = 'unknown'
      stream_id = int(struct.unpack('<H', asf_head[i + 72 : i + 74])[0])
      assert stream_id <= ASF_MAX_NUM_STREAMS, 'Bad stream_id=%d' % stream_id
      assert stream_id not in stream_ids
      #print (stream_id, stream_type)
      stream_ids[stream_id] = stream_type
    elif guid_hex == GUID_ASF_STREAM_BITRATE_PROPERTIES:
      assert size >= 26
      stream_count_now = int(struct.unpack('<H', asf_head[i + 24 : i + 26])[0])
      assert size >= 26 + 6 * stream_count_now
      for j in xrange(0, stream_count_now):
        stream_id, bitrate = struct.unpack(
            '<HL', asf_head[i + 26 + j * 6 : i + 32 + j * 6])
        assert stream_id <= ASF_MAX_NUM_STREAMS, 'Bad stream_id=%d' % stream_id
        bitrate = int(bitrate)
        stream_bitrates[stream_id] = bitrate
        stream_bitrates_pos[stream_id] = i + 28 + j * 6
    elif guid_hex == GUID_ASF_DATA:
      # This usually has size > 65535.
      packet_count = int(struct.unpack('<Q', asf_head[i + 40 : i + 48])[0])
    if size > 65535:
      # Example: size=0xaba1b2 remaining=0x32
      # assert 0, 'size=0x%x remaining=0x%x' % (size, len(asf_head) - i)
      i = len(asf_head)
      break
    assert i + size <= len(asf_head), (i + size, size, len(asf_head))
    i += size
  assert i == len(asf_head)
  assert packet_size > 0, 'Could not find packet_size in ASF header.'
  return {
      'packet_size': packet_size,
      'file_size': file_size,
      'packet_count': packet_count,
      'stream_ids': stream_ids,
      'stream_bitrates': stream_bitrates,
      'stream_bitrates_pos': stream_bitrates_pos,
  }


def DoFirstAsfRequest(url):
  # request-context below is the HTTP request counter.
  headers = (
      'Accept: */*',
      'User-Agent: NSPlayer/4.1.0.3856',
      'Pragma: no-cache,rate=1.000000,stream-time=0,stream-offset=0:0,request-context=1,max-duration=0',
      'Pragma: xClientGUID={c77e7400-738a-11d2-9add-0020af0a3278}',
  )
  # TODO(pts): Open the other source after timeout.
  f = DoHttpRequest(url, headers)

  try:
    # Read and parse the ASF header.
    asf_head = ''
    while True:
      chunk_head = f.read(4)
      if asf_head and not chunk_head:
        break
      assert len(chunk_head) == 4, 'Unexpected EOF in chunk_head=%r' % (
          chunk_head)
      chunk_type, chunk_size = struct.unpack('<HH', chunk_head)
      assert chunk_type == CHUNK_TYPE_ASF_HEADER, (
          'Expected chunk ASF header, got chunk_type=0x%x' % chunk_type)
      ext_header_size = EXT_HEADER_SIZES[chunk_type]
      ext_head = f.read(ext_header_size)
      assert len(ext_head) == ext_header_size
      chunk_size -= ext_header_size
      assert len(asf_head) + chunk_size <= ASF_MAX_HEADER_SIZE, (
          'ASF header too long.')
      chunk_data = f.read(chunk_size)
      assert len(chunk_data) == chunk_size
      asf_head += chunk_data
      del chunk_data

    return ParseAsfHeader(asf_head)
  finally:
    f.close()


ZERO4_ARY = array.array('c', '\0\0\0\0')


def GetAsfHeaderWithStreamsDisabled(
    asf_head, asf_info, enabled_stream_ids):
  stream_bitrates_pos = asf_info['stream_bitrates_pos']
  if not set(stream_bitrates_pos).difference(enabled_stream_ids):
    return asf_head  # All streams enabled, unchanged.
  asf_head_ary = array.array('c', asf_head)
  # Set bitrate of non-enabled streams to 0, so the video player wouldn't
  # accidentally select them for playing. (Doesn't affect mplayer: mplayer
  # would happily play those streams.)
  for stream_id in sorted(stream_bitrates_pos):
    if stream_id not in enabled_stream_ids:
      bitrate_pos = stream_bitrates_pos[stream_id]
      asf_head_ary[bitrate_pos : bitrate_pos + 4] = ZERO4_ARY
  return asf_head_ary.tostring()


def DownloadAsfStreamData(f, outf, enabled_stream_ids):
  # TODO(pts): Add support for live streams.
  expected_seq = 0
  processed_asf_header = False
  pos = 0
  asf_head = ''
  packet_size = 0
  out_pos = 0
  sys.stderr.write('Downloading stream...')
  max_msg_size = 0
  start_ts = time.time()
  while True:  # It's an error not to have the END chunk.
    chunk_pos = pos
    chunk_head = f.read(4)
    pos += len(chunk_head)
    assert len(chunk_head) == 4, 'Unexpected EOF in chunk_head=%r' % chunk_head
    chunk_type, chunk_size = struct.unpack('<HH', chunk_head)
    ext_header_size = EXT_HEADER_SIZES.get(chunk_type)
    assert ext_header_size is not None, 'Unknown chunk type=0x%x' % chunk_type
    ext_head = f.read(ext_header_size)
    pos += len(ext_head)
    chunk_size -= ext_header_size
    assert len(ext_head) == ext_header_size

    if chunk_type == CHUNK_TYPE_DATA:
      seq = int(struct.unpack('<L', ext_head[:4])[0])
      assert expected_seq == seq, 'Bad seq: expected=%d got=%d' % (
          expected_seq, seq)
      expected_seq += 1
    elif chunk_type == CHUNK_TYPE_END:
      seq = int(struct.unpack('<L', ext_head[:4])[0])
      assert seq in (0, 1), 'Unexpected seq=%d for END' % seq
      if seq == 1:
        raise NotImplementedError('Subsequent HTTP request not supported.')
      break
    elif chunk_type == CHUNK_TYPE_RESET:
      asf_head = ''
      processed_asf_header = False
      assert chunk_size, 'Unexpected chunk_size=%d' % chunk_size
    elif chunk_type == CHUNK_TYPE_ASF_HEADER:
      assert not processed_asf_header, 'Unexpected ASF_HEADER.'
      assert len(asf_head) + chunk_size <= ASF_MAX_HEADER_SIZE, (
          'ASF header too long.')
    else:
      assert 0, 'Unexpected chunk type=0x%x' % chunk_type

    if chunk_type != CHUNK_TYPE_ASF_HEADER and not processed_asf_header:
      # All chunks of the ASF header has been read, interpret asf_head.
      asf_info = ParseAsfHeader(asf_head)
      packet_size = asf_info['packet_size']
      if asf_info.get('packet_count') is not None:
        # Usually asf_info['file_size'] is longer (about 6.45 bytes per second)
        # than this one, because the ASF file contains an index after the
        # data stream -- but it's not possible to download that index using
        # mmsh:// , so for our purposes the size of the file is without the
        # index.
        file_size = len(asf_head) + asf_info['packet_count'] * packet_size
      else:
        file_size = asf_info.get('file_size')
      asf_head = GetAsfHeaderWithStreamsDisabled(
          asf_head, asf_info, enabled_stream_ids)
      outf.write(asf_head)
      out_pos += len(asf_head)
      asf_head = ''  # Save memory.
      processed_asf_header = True

    # CHUNK_TYPE_DATA has mms seq in ext_head[5]
    # CHUNK_TYPE_DATA and CHUNK_TYPE_ASF_HEADER have len2 in ext_head[6 : 8]
    chunk_data = f.read(chunk_size)
    pos += len(chunk_data)
    assert len(chunk_data) == chunk_size
    if chunk_type == CHUNK_TYPE_DATA:
      assert chunk_size <= packet_size, 'Bad chunk_size=%d, packet_size=%d' % (
          chunk_size, packet_size)
      outf.write(chunk_data)
      if packet_size > chunk_size:
        outf.write('\0' * (packet_size - chunk_size))  # Padding.
      out_pos += packet_size
      now_ts = time.time()
      # Download speed: out_pos / (now_ts - start_ts).
      # Exp. total download time: file_size / (out_pos / (now_ts - start_ts)).
      # Expected remaining download time:
      #     (now_ts - start_ts) * (file_size / out_pos - 1).
      eta = (now_ts - start_ts) * ((file_size + 0.0) / out_pos - 1)
      if file_size:
        msg = 'Downloaded %d of %d bytes (%.2f%%), ETA %ds...' % (
            out_pos, file_size,
            (100.0 * out_pos / file_size),
            int(eta + .999999))
      else:
        msg = 'Downloaded %d bytes in %ds...' % (out_pos, int(now_ts - start_ts))
      max_msg_size = max(max_msg_size, len(msg))
      sys.stderr.write('\r' + msg)
      sys.stderr.flush()
    elif chunk_type == CHUNK_TYPE_ASF_HEADER:
      asf_head += chunk_data
    assert len(chunk_data) == chunk_size
  # TODO(pts): Do this in a `finally:' block.
  sys.stderr.write('\r' + ' ' * max_msg_size)
  duration = time.time() - start_ts
  print >>sys.stderr, '\rDownload finished (%d bytes) in %ds.' % (
      out_pos, int(duration + .999999))
  sys.stderr.flush()


STREAM_ENABLE_FLAG = [2, 0]
"""2 means disabled, 0 means enabled."""


def DoSecondAsfRequest(url, outf, stream_ids, enabled_stream_ids):
  request_context = 2  # The HTTP request counter.
  stream_time = 0
  stream_selection = ' '.join(
       'ffff:%d:%d' %
       (stream_id, STREAM_ENABLE_FLAG[stream_id in enabled_stream_ids])
       for stream_id in sorted(stream_ids))
  headers = (
      'Accept: */*',
      'User-Agent: NSPlayer/4.1.0.3856',
      'Pragma: no-cache,rate=1.000000,stream-time=%d,stream-offset=0:0,request-context=%d,max-duration=0' % (request_context, stream_time),
      'Pragma: xClientGUID={c77e7400-738a-11d2-9add-0020af0a3278}',
      'Pragma: xPlayStrm=1',
      'Pragma: stream-switch-count=%d' % len(stream_ids),
      'Pragma: stream-switch-entry=%s' % stream_selection,
  )
  del stream_time, stream_selection
  f = DoHttpRequest(url, headers)
  try:
    DownloadAsfStreamData(f, outf, enabled_stream_ids)
  finally:
    f.close()


def FindHighestQualityStream(asf_info, stream_type):
  """Returns a stream ID (nonnegative integer) or None."""
  stream_ids = asf_info['stream_ids']
  stream_bitrates = asf_info['stream_bitrates']
  max_bitrate = -2
  best_stream_id = None
  for cur_stream_id in sorted(stream_ids):
    if stream_type == stream_ids[cur_stream_id]:
      cur_bitrate = stream_bitrates.get(cur_stream_id, -1)
      # Ignore streams with bitrate 0.
      if cur_bitrate != 0 and cur_bitrate > max_bitrate:
        max_bitrate = cur_bitrate
        best_stream_id = cur_stream_id
  return best_stream_id


def DownloadMmsh(url, save_filename):
  assert url.startswith('mmsh://')
  print >>sys.stderr, 'Downloading MMS from %s' % url
  print >>sys.stderr, 'Will save ASF to %s' % save_filename
  asf_info = DoFirstAsfRequest(url)
  audio_stream_id = FindHighestQualityStream(asf_info, 'audio')
  video_stream_id = FindHighestQualityStream(asf_info, 'video')
  assert not (audio_stream_id is None and video_stream_id is None), (
      'Missing audio and video stream, asf_info=%r' % asf_info)
  enabled_stream_ids = set(
      stream_id for stream_id in (audio_stream_id, video_stream_id)
      if stream_id is not None)
  print >>sys.stderr, 'Saving    ASF to %s' % save_filename
  outf = open(save_filename, 'wb')
  try:
    DoSecondAsfRequest(url, outf, asf_info['stream_ids'], enabled_stream_ids)
  finally:
    outf.close()


def DownloadHttp(url, save_filename):
  assert url.startswith('http://')
  # TODO(pts): Continue a previously broken download.
  print >>sys.stderr, 'Downloading HTTP from %s' % url
  print >>sys.stderr, 'Will save to %s' % save_filename
  outf = open(save_filename, 'wb')
  try:
    content_length_ary = []
    f = DoHttpRequest(url, content_length_out=content_length_ary)
    if content_length_ary:
      bytes_remaining = content_length_ary[-1]
    else:
      bytes_remaining = None
    try:
      sys.stderr.write('Downloading HTTP stream...')
      max_msg_size = 0
      out_pos = 0
      start_ts = time.time()
      while True:
        # TODO(pts): Count Content-Length, abort on a partial download.
        data = f.read(65536)
        if not data:
          break
        assert bytes_remaining is None or len(data) <= bytes_remaining, (
            'Too many bytes read.')
        bytes_remaining -= len(data)
        outf.write(data)
        outf.flush()
        out_pos += len(data)
        now_ts = time.time()
        if content_length_ary:
          file_size = content_length_ary[-1]
          eta = (now_ts - start_ts) * ((file_size + 0.0) / out_pos - 1)
          # TODO(pts): Remove up to EOL of previous msg was longer.
          msg = 'Downloaded %d of %d bytes (%.2f%%), ETA %ds...' % (
              out_pos, file_size,
              (100.0 * out_pos / file_size),
              int(eta + .999999))
        else:
          msg = 'Downloaded %d bytes in %ds...' % (out_pos, int(now_ts - start_ts))
        max_msg_size = max(max_msg_size, len(msg))
        sys.stderr.write('\r' + msg)
        sys.stderr.flush()
      assert not bytes_remaining, (
          'Download aborted too early, %d bytes remaining.' % bytes_remaining)
      # TODO(pts): Do this in a `finally:' block.
      sys.stderr.write('\r' + ' ' * max_msg_size)
      duration = time.time() - start_ts
      print >>sys.stderr, '\rDownload finished (%d bytes) in %ds.' % (
          out_pos, int(duration + .999999))
      sys.stderr.flush()
    finally:
      f.close()
  finally:
    outf.close()


def GuessSaveFilenameFromUrl(url, orig_url):
  force_ext = ''
  if orig_url.startswith('http://tv2.hu/'):
    match = re.search(r'[.]\w+\Z', url)
    if match:
      force_ext = match.group(0)
    url = orig_url
  elif url.startswith('rtmp'):
    force_ext = '.flv'  # Or keep .mp4?
  save_filename = re.sub(r'(?s)[?].*\Z', '', url)
  save_filename = save_filename[save_filename.rfind('/') + 1 :]
  if save_filename.startswith('mp4:'):  # rtmp://flash1.atv.hu/vod/mp4:120607_huzos_2.mp4
    save_filename = save_filename[4:]
  save_filename = re.sub(
      r'%([a-fA-F0-9]{2})',
      lambda match: chr(int(match.group(1), 16)),
      save_filename.replace('+', ' '))
  save_filename = re.sub(
      r'[^-.\w]',
      lambda match: '%%%02X' % ord(match.group(0)), save_filename)
  name, ext = os.path.splitext(save_filename)
  if force_ext:
    ext = force_ext.lower()
  else:
    ext = ext.lower()
    if ext not in ('.asf', '.wmv'):
      ext += '.wmv'
  return name + ext


def GetMtvStreamUrl(url):
  # originally by pts@fazekas.hu at Sat Feb 18 10:18:45 CET 2012
  # adapted at Sat Mar 31 11:51:25 CEST 2012
  # Example: http://videotar.mtv.hu/Kategoriak/Maradj%20talpon.aspx
  # -> http://streamer.carnation.hu/mtvod2/maradj_taplon/2012/02/17/maradj_talpon_20120217.wmv
  # -> mmsh://streamer2.carnation.hu/mtvod2/maradj_taplon/2012/02/17/maradj_talpon_20120217.wmv?MSWMExt=.asf
  print >>sys.stderr, 'Getting Mtv stream URL for: %s' % url
  assert url.startswith('http://videotar.mtv.hu/')
  data = DoHttpRequest(url).read()
  # ShowVideo('http://streamer.carnation.hu/mtvod2/maradj_taplon/2012/02/17/maradj_talpon_20120217.wmv', '');
  matches = re.findall(r'["\'](http://streamer[.]carnation[.]hu/[^&"\'\\?]+[.]wmv)["\']', data)
  assert len(matches) == 1, matches
  url2 = matches[0]
  data = DoHttpRequest(url2).read().strip()
  # '<asx version="3.0">\n  <title>MTV Online Live Stream</title>\n  <entry>\n'
  # '    <title>www.mtv.hu</title>\n\n\t    <ref href="http://streamer2.'
  # 'carnation.hu/mtvod2/maradj_taplon/2012/02/17/maradj_talpon_20120217.wmv"'
  # ' />\n\t    <ref href="http://streamer3.carnation.hu/mtvod2/maradj_taplon/'
  # '2012/02/17/maradj_talpon_20120217.wmv" />    <author>MTV</author>\n'
  # '    <copyright>(c) 2008 www.mtv.hu</copyright>\n  </entry>\n</asx>\n'
  assert data.startswith('<asx ')
  # TODO(pts): If streamer2 returns a 404 error for the real stream, use streamer3 automatically.
  matches = re.findall(r'["\'](http://streamer\d+[.]carnation[.]hu/[^&"\'\\?]+[.]wmv)["\']', data)
  assert matches
  url3 = matches[0]  # There are usually 2 matches in random order.
  return re.sub(r'\A\w+://', 'mmsh://', url3, 1) + '?MSWMExt=.asf'


def GetAtvStreamUrl(url):
  # at Sun Jun 10 12:09:08 CEST 2012
  # Example: http://atv.hu/videotar/20120608_csernus_imre
  # -> rtmp://flash1.atv.hu/vod/mp4:120607_huzos_2.mp4
  print >>sys.stderr, 'Getting Atv stream URL for: %s' % url
  assert url.startswith('http://atv.hu/videotar/')
  data = DoHttpRequest(url).read()
  matches = set(re.findall(r'=["\']?(rtmp://[^&"\'\\]+)[&"\']', data))
  assert len(matches) == 1, matches
  return iter(matches).next()


def GetEurosportStreamUrl(url):
  # by pts@fazekas.hu at Wed May 23 14:37:02 CEST 2012
  # Example: (http://www.eurosportplayer.com/video_cuv13185742.shtml)
  # -> eurosport:lang=0,geoloc=HU,realip=80.98.123.212,ut=9c0762c2-c644-e011-a60b-1cc1deedf59c,ht=36b9eef9fd30796487427dab42834737,vidid=-1,cuvid=13185742,prdid=-1
  # -> mmsh://vodstream.eurosport.com/nogeo/_!/catchup/20/G1_2113185742AA.wmv?auth=dbFcHcKdta3bwcBbpbhdRcHc3aHakdUb5d8-bpVnA0-U4-frG-HzsELAskx
  #
  # Firefox bookmarklet for generating the eurosport: URL: javascript:d=document.getElementsByTagName('param');for(i=0;i<d.length;++i){if(d[i].name=='InitParams'){e=document.createElement('div');e.appendChild(document.createTextNode('eurosport:'+d[i].value));e.style.background='#fff';e.style.color='#f00';document.body.insertBefore(e,document.body.firstChild)}}void(0)
  print >>sys.stderr, 'Getting Eurosport stream URL for: %s' % url
  assert url.startswith('eurosport:')
  # Example: <param name="InitParams" value="lang=0,geoloc=HU,realip=80.98.123.212,ut=9c0762c2-c644-e011-a60b-1cc1deedf59c,ht=36b9eef9fd30796487427dab42834737,vidid=-1,cuvid=13103566,prdid=-1" />
  init_params = url.split(':', 1)[1]
  init_params_dict = {}
  for pair in init_params.split(','):
    if pair:
      name, value = pair.split('=', 1)
      init_params_dict[name] = value
  # TODO(pts): Escape XML text.
  post_data = (
      '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
      '<s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
      '<GetCatchUpVideoSecurized xmlns="http://tempuri.org/">'
      '<catchUpVideoId>%(cuvid)s</catchUpVideoId>'
      '<geolocCountry>%(geoloc)s</geolocCountry>'
      '<realIp>%(realip)s</realIp>'
      '<userId>%(ut)s</userId>'
      '<hkey>%(ht)s</hkey>'
      '<responseLangId>%(lang)s</responseLangId>'
      '</GetCatchUpVideoSecurized>'
      '</s:Body>'
      '</s:Envelope>' % init_params_dict)
  response = DoHttpRequest(
      'http://videoshop.eurosport.com/PlayerCatchupService.asmx',
      request_headers=(
          'Referer: http://www.eurosportplayer.com/layout/x/PlayerSL4.xap\r\n',
          'Content-Type: text/xml; charset=utf-8\r\n',
          'SOAPAction: "http://tempuri.org/GetCatchUpVideoSecurized"\r\n',
      ),
      post_data=post_data).read()
  good_url = None
  for content_str in re.findall(r'(?m)<catchupstream>(.*?)</catchupstream>', response):
    match = re.search(r'(?m)<lang>\d+</lang>\s*<name>([^<]*?)</name>', content_str)
    if match:
      language = match.group(1)
    else:
      match = re.search(r'(?m)<lang>\d+</lang>\s*<name\s*/>', content_str)
      assert match, repr(content_str)
      language = ''  # !! Autonumber.
    match = re.search(r'(?m)<securizedurl>mmsh?://([^<]*?)</securizedurl>', content_str)
    url = 'mmsh://' + match.group(1)
    if language.lower() == 'english':
      good_url = url
  assert good_url is not None, response
  # TODO(pts): Distinguish streams betwen same URL for multiple languages.
  # {'mmsh://vodstream.eurosport.com/nogeo/_!/catchup/21/G4_1813103566A0.wmv?auth=dbFa9cUa_aJcYbaagdvc9bxdndzbJbydbd0-bpVngw-U4-frG-FzsBFAslv': ['Finnish', 'Norwegian', 'Romanian', 'Czech'],
  #  'mmsh://vodstream.eurosport.com/nogeo/_!/catchup/21/G1_1713103566A0.wmv?auth=dbFcmcScBaXdFa4bQcpavcfc.dibnd.crdr-bpVngw-U4-frG-GzqDJAwmw': ['English', 'German', 'Spanish'],
  #  'mmsh://vodstream.eurosport.com/nogeo/_!/catchup/21/G3_1813103566A0.wmv?auth=dbFb1awavcmaWata5bkd2cOcmb4dRcibjbz-bpVngw-U4-frG-HxoBDCpjD': ['Dutch', 'Swedish', 'Portuguese', 'Danish'],
  #  'mmsh://vodstream.eurosport.com/nogeo/_!/catchup/21/G2_1713103566A0.wmv?auth=dbFaKd.bvcaclcncsb.bRd1aadLcgcGaoa3-bpVngw-U4-frG-KAoCDCnlw': ['', '', 'Polish', 'Russian']}
  # {'stream_bitrates': {1: 705965, 2: 49059, 3: 49059, 4: 49059, 5: 49059}, 'stream_bitrates_pos': {1: 6003, 2: 6009, 3: 6015, 4: 6021, 5: 6027}, 'packet_size': 16000, 'packet_count': 39783, 'stream_ids': {1: 'video', 2: 'audio'}, 'file_size': 636682253}
  return good_url


def GetTv2StreamUrl(url):
  # copied from webcast.py
  # at Thu Oct 14 22:08:27 CEST 2010
  # then copied from xmplayer

  assert url.startswith('http://tv2.hu/')
  print >>sys.stderr, 'Getting Tv2 stream URL for: %s' % url

  data = DoHttpRequest(url).read()
  # playlistURL: 'http://tv2.hu/edesnegyes/video/zana-jozsef-egy-non-akar-meghalni/player/xml'
  match = re.search(r'\bplaylistURL:\s*\'(http://[^\'"\\&]+)\'', data)
  assert match
  url2 = match.group(1)

  data = DoHttpRequest(url2).read()
  # Example:
  #                <URL reference="true">
  #                        <![CDATA[http://streamctl.tv2.hu/bydate/20101002/55018.flv]]>
  #                </URL>
  # Example 2:
  #   <URL reference="true"><![CDATA[http://streamctl.tv2.hu/vod2/20120217/id_85163]]></URL>
  match = re.search('(?s)<URL[ >].*?(http://[^\]<>"&]+(?:[.](?:flv|mp4)|/id_\d+))[\]<>]', data)
  assert match, data
  url3 = match.group(1)

  #print >>sys.stderr, 'url3: %s' % url3
  data = DoHttpRequest(url3).read()
  # <url>http://pstream5.tv2.hu/bydate/20101002/55018.flv</url>
  # <url>http://pstream3.tv2.hu/vod4/20120217/85163.phone_h264_800k.mp4?st=epj35Dl7YW7Dvqtc2uwPwA&amp;e=1329650150</url>
  match = re.search('(http://[^<>&"?]+[.](?:flv|mp4))(?:\s*<|[?])', data)
  assert match, data
  url4 = match.group(1)

  # mplayer can play this stream directly, and download managers can download
  # the file directly.
  return url4


def DownloadRtmp(url, save_filename):
  match = re.match(r'\A(\w+)://([^/]+)/', url)
  assert match, repr(url)
  protocol = match.group(1)
  host = match.group(2)
  assert protocol in ('rtmp', 'rtmpt', 'rtmpe', 'rtmpte', 'rtmps'), repr(url)
  cmd = ['rtmpdump', '-o', save_filename, '-r', url, '-t', url]
  if host.endswith('.atv.hu'):
    # Works for rtmp://flash1.atv.hu/vod/mp4:120607_huzos_2.mp4"
    # at Sun Jun 10 12:27:28 CEST 2012
    cmd.extend(('-s', 'http://static.atv.hu/'))
  cmd_str = ' '.join(map(ShellQuote, cmd))
  print >>sys.stderr, 'Running: ' + cmd_str
  status = os.system(cmd_str)
  if status:
    print >>sys.stderr, (
        'External command (rtmpdump) failed with status 0x%x' % status)
    sys.exit(3)


def main(argv):
  if len(argv) not in (2, 3):
    print >>sys.stderr, 'Usage: %s <mmsh-url> [<save-filename>]' % argv[0]
    print >>sys.stderr, 'Use this program to download mmsh:// streams.'
    return 1
  orig_url = url = argv[1]
  if url.startswith('http://videotar.mtv.hu/'):
    url = GetMtvStreamUrl(url)
  elif url.startswith('http://tv2.hu/'):
    url = GetTv2StreamUrl(url)
  elif url.startswith('eurosport:'):
    url = GetEurosportStreamUrl(url)
  elif url.startswith('http://atv.hu/videotar/'):
    url = GetAtvStreamUrl(url)
  if len(argv) > 2:
    save_filename = argv[2]
  else:
    save_filename = GuessSaveFilenameFromUrl(url, orig_url)
  match = re.match(r'\A([a-zA-Z]\w+)://', url)
  assert match, 'Invalid protocol for URL: ' + url
  protocol = match.group(1).lower()
  if protocol == 'http':  # https:// is not supported.
    DownloadHttp(url, save_filename)
  elif protocol == 'mmsh':
    DownloadMmsh(url, save_filename)
  elif protocol in ('rtmp', 'rtmpt', 'rtmpe', 'rtmpte', 'rtmps'):
    DownloadRtmp(url, save_filename)
  else:
    print >>sys.stderr, 'Unsupported protocol for URL: ' + url
    return 2


if __name__ == '__main__':
  sys.exit(main(sys.argv))
