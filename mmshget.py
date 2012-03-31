#! /usr/bin/python2.4
# by pts@fazekas.hu at Sat Mar 24 17:32:25 CET 2012

import array
import os
import re
import socket
import struct
import sys
import time

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


def DoHttpRequest(url, request_headers=(), timeout=10):
  """Send a HTTP GET request.
  
  Args:
    url: String containing an http:// or mmsh:// URL.
    request_headers: Sequence of strings containing request headers to send.
    timeout: Timeout for each socket operation, in seconds.
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

  proxy_address = GetProxyForHost(host)
  if proxy_address:
    connect_address = proxy_address
    req = ['GET http://%s%s HTTP/1.0\r\nHost: %s\r\n' %
           (hostport, path, hostport)]
  else:
    connect_address = (host, port)
    req = ['GET %s HTTP/1.0\r\nHost: %s\r\n' % (path, hostport)]
  for header in request_headers:
    header = header.rstrip('\r\n')
    if header:
      assert ':' in header, 'Missing colon in request_header=%r' % (header,)
      assert '\n' not in header, (
          'Unexpected newline in request_header=%r' % (header,))
      assert '\r' not in header, (
          'Unexpected CR in request_header=%r' % (header,))
      req.append(header + '\r\n')
  req.append('\r\n')
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

# base ASF objects
GUID_HEADER = '3026b2758e66cf11a6d900aa0062ce6c'
GUID_ASF_DATA = '3626b2758e66cf11a6d900aa0062ce6c'
GUID_SIMPLE_INDEX = '90080033b1e5cf1189f400a0c90349cb'
GUID_INDEX = 'd329e2d6da35d111903400a0c90349be'
GUID_MEDIA_OBJECT_INDEX = 'f803b1fead12644c840f2a1d2f7ad48c'
GUID_TIMECODE_INDEX = 'd03fb73c4a0c0348953dedf7b6228f0c'
# header ASF objects
GUID_ASF_FILE_PROPERTIES = 'a1dcab8c47a9cf118ee400c00c205365'
GUID_ASF_STREAM_PROPERTIES = '9107dcb7b7a9cf118ee600c00c205365'
GUID_HEADER_EXTENSION = 'b503bf5f2ea9cf118ee300c00c205365'
GUID_CODEC_LIST = '4052d1861d31d011a3a400a0c90348f6'
GUID_SCRIPT_COMMAND = '301afb1e620bd011a39b00a0c90348f6'
GUID_MARKER = '01cd87f451a9cf118ee600c00c205365'
GUID_BITRATE_MUTUAL_EXCLUSION = 'dc29e2d6da35d111903400a0c90349be'
GUID_ERROR_CORRECTION = '3526b2758e66cf11a6d900aa0062ce6c'
GUID_CONTENT_DESCRIPTION = '3326b2758e66cf11a6d900aa0062ce6c'
GUID_EXTENDED_CONTENT_DESCRIPTION = '40a4d0d207e3d21197f000a0c95ea850'
# (http://get.to/sdp)
GUID_ASF_STREAM_BITRATE_PROPERTIES = 'ce75f87b8d46d1118d82006097c9a2b2'
GUID_EXTENDED_CONTENT_ENCRYPTION = '14e68a292226174cb935dae07ee9289c'
GUID_PADDING = '74d40618dfca0945a4ba9aabcb96aae8'
# stream properties object stream type
GUID_ASF_AUDIO_MEDIA = '409e69f84d5bcf11a8fd00805f5c442b'
GUID_ASF_VIDEO_MEDIA = 'c0ef19bc4d5bcf11a8fd00805f5c442b'
GUID_ASF_COMMAND_MEDIA = 'c0cfda59e659d011a3ac00a0c90348f6'
GUID_ASF_JFIF_MEDIA = '00e11bb64e5bcf11a8fd00805f5c442b'
GUID_ASF_DEGRADABLE_JPEG_MEDIA = 'e07d903515e4cf11a91700805f5c442b'
GUID_FILE_TRANSFER_MEDIA = '2c22bd911cf27a498b6d5aa86bfc0185'
GUID_BINARY_MEDIA = 'e265fb3aef47f240ac2c70a90d71d343'
# stream properties object error correction
GUID_NO_ERROR_CORRECTION = '0057fb20555bcf11a8fd00805f5c442b'
GUID_AUDIO_SPREAD = '50cdc3bf8f61cf118bb200aa00b4e220'
# mutual exclusion object exlusion type
GUID_MUTEX_BITRATE = '012ae2d6da35d111903400a0c90349be'
GUID_MUTEX_UNKNOWN = '022ae2d6da35d111903400a0c90349be'
# header extension
GUID_RESERVED_1 = '11d2d3abbaa9cf118ee600c00c205365'
# script command
GUID_RESERVED_SCRIPT_COMMAND = 'e3cb1a4b0b10d011a39b00a0c90348f6'
# marker object
GUID_RESERVED_MARKER = '20dbfe4cf675cf119c0f00a0c90349cb'
# various
# Already defined (reserved_1)
GUID_HEAD2 = '11d2d3abbaa9cf118ee600c00c205365'
GUID_AUDIO_CONCEAL_NONE = '40a4f149ce4ed011a3ac00a0c90348f6'
GUID_CODEC_COMMENT1_HEADER = '4152d1861d31d011a3a400a0c90348f6'
GUID_ASF_20_HEADER = 'd129e2d6da35d111903400a0c90349be'

# !! In idojaras:
# 3326b2758e66cf11a6d900aa0062ce6c GUID_CONTENT_DESCRIPTION
# 40a4d0d207e3d21197f000a0c95ea850 GUID_EXTENDED_CONTENT_DESCRIPTION
# 4052d1861d31d011a3a400a0c90348f6 GUID_CODEC_LIST
# a1dcab8c47a9cf118ee400c00c205365 GUID_FILE_PROPERTIES
# b503bf5f2ea9cf118ee300c00c205365 GUID_HEADER_EXTENSION
# 9107dcb7b7a9cf118ee600c00c205365 GUID_ASF_STREAM_PROPERTIES
# 9107dcb7b7a9cf118ee600c00c205365 GUID_ASF_STREAM_PROPERTIES (again)
# ce75f87b8d46d1118d82006097c9a2b2 GUID_STREAM_BITRATE_PROPERTIES
# 3626b2758e66cf11a6d900aa0062ce6c GUID_ASF_DATA

def ParseAsfHeader(asf_head):
  assert asf_head, 'Missing ASF header.'
  i = 30
  packet_size = 0
  file_size = None
  stream_ids = {}
  stream_bitrates = {}
  stream_bitrates_pos = {}   # !! use this
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
      print bitrate_pos
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
    # print '@%d' % pos
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
    #print '@%d headext_size=%d type=%s size=%d' % (
    #    chunk_pos, 4 + ext_header_size, NAME_FROM_TYPE[chunk_type], chunk_size)

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
    # print 'DUMP size=%d %r' % (len(chunk_data), chunk_data)
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
        # TODO(pts): Print an ETA.
        msg = 'Downloaded %d of %d bytes (%.2f%%), ETA %ds...' % (
            out_pos, file_size,
            (100.0 * out_pos / file_size),
            int(eta + .999999))
      else:
        msg = 'Downloaded %d bytes...'
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


if __name__ == '__main__':
  url = 'http://streamer3.carnation.hu/mtvod2/hirado/2012/03/14/idojaras_20120314_122.wmv?MSWMExt=.asf'
  asf_info = DoFirstAsfRequest(url)
  audio_stream_id = FindHighestQualityStream(asf_info, 'audio')
  video_stream_id = FindHighestQualityStream(asf_info, 'video')
  #assert 0, (asf_info, audio_stream_id, video_stream_id)
  assert not (audio_stream_id is None and video_stream_id is None), (
      'Missing audio and video stream, asf_info=%r' % asf_info)
  enabled_stream_ids = set(
      stream_id for stream_id in (audio_stream_id, video_stream_id)
      if stream_id is not None)
  outf = open('dump.asf', 'w')
  DoSecondAsfRequest(url, outf, asf_info['stream_ids'], enabled_stream_ids)
