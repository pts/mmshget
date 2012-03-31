#! /usr/bin/python2.4

import struct

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

# base ASF objects
GUID_HEADER = '3026b2758e66cf11a6d900aa0062ce6c'
GUID_DATA = '3626b2758e66cf11a6d900aa0062ce6c'
GUID_SIMPLE_INDEX = '90080033b1e5cf1189f400a0c90349cb'
GUID_INDEX = 'd329e2d6da35d111903400a0c90349be'
GUID_MEDIA_OBJECT_INDEX = 'f803b1fead12644c840f2a1d2f7ad48c'
GUID_TIMECODE_INDEX = 'd03fb73c4a0c0348953dedf7b6228f0c'
# header ASF objects
GUID_ASF_FILE_PROPERTIES = 'a1dcab8c47a9cf118ee400c00c205365'
GUID_STREAM_HEADER = '9107dcb7b7a9cf118ee600c00c205365'
GUID_HEADER_EXTENSION = 'b503bf5f2ea9cf118ee300c00c205365'
GUID_CODEC_LIST = '4052d1861d31d011a3a400a0c90348f6'
GUID_SCRIPT_COMMAND = '301afb1e620bd011a39b00a0c90348f6'
GUID_MARKER = '01cd87f451a9cf118ee600c00c205365'
GUID_BITRATE_MUTUAL_EXCLUSION = 'dc29e2d6da35d111903400a0c90349be'
GUID_ERROR_CORRECTION = '3526b2758e66cf11a6d900aa0062ce6c'
GUID_CONTENT_DESCRIPTION = '3326b2758e66cf11a6d900aa0062ce6c'
GUID_EXTENDED_CONTENT_DESCRIPTION = '40a4d0d207e3d21197f000a0c95ea850'
# (http://get.to/sdp)
GUID_STREAM_BITRATE_PROPERTIES = 'ce75f87b8d46d1118d82006097c9a2b2'
GUID_EXTENDED_CONTENT_ENCRYPTION = '14e68a292226174cb935dae07ee9289c'
GUID_PADDING = '74d40618dfca0945a4ba9aabcb96aae8'
# stream properties object stream type
GUID_AUDIO_MEDIA = '409e69f84d5bcf11a8fd00805f5c442b'
GUID_VIDEO_MEDIA = 'c0ef19bc4d5bcf11a8fd00805f5c442b'
GUID_COMMAND_MEDIA = 'c0cfda59e659d011a3ac00a0c90348f6'
GUID_JFIF_MEDIA_JPEG = '00e11bb64e5bcf11a8fd00805f5c442b'
GUID_DEGRADABLE_JPEG_MEDIA = 'e07d903515e4cf11a91700805f5c442b'
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
# 9107dcb7b7a9cf118ee600c00c205365 GUID_STREAM_HEADER
# 9107dcb7b7a9cf118ee600c00c205365 GUID_STREAM_HEADER (again)
# ce75f87b8d46d1118d82006097c9a2b2 GUID_STREAM_BITRATE_PROPERTIES
# 3626b2758e66cf11a6d900aa0062ce6c GUID_DATA

f = open('g2.asf')
outf = open('g2.asf.dump', 'w')
expected_seq = 0
processed_asf_header = False
pos = 0
asf_head = ''
packet_size = 0
while True:  # It's an error not to have the END chunk.
  chunk_pos = pos
  print '@%d' % pos
  chunk_head = f.read(4)
  pos += len(chunk_head)
  assert len(chunk_head) == 4
  chunk_type, chunk_size = struct.unpack('<HH', chunk_head)
  ext_header_size = EXT_HEADER_SIZES.get(chunk_type)
  assert ext_header_size is not None, 'Unknown chunk type=0x%x' % chunk_type
  ext_head = f.read(ext_header_size)
  pos += len(ext_head)
  chunk_size -= ext_header_size
  print '@%d headext_size=%d type=%s size=%d' % (
      chunk_pos, 4 + ext_header_size, NAME_FROM_TYPE[chunk_type], chunk_size)

  if chunk_type == CHUNK_TYPE_DATA:
    seq, = struct.unpack('<L', ext_head[:4])
    assert expected_seq == seq, 'Bad seq: expected=%d got=%d' % (
        expected_seq, seq)
    expected_seq += 1
  elif chunk_type == CHUNK_TYPE_END:
    seq, = struct.unpack('<L', ext_head[:4])
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
    assert len(asf_head) + chunk_size <= 16384, 'ASF header too long.'
  else:
    assert 0, 'Unexpected chunk type=0x%x' % chunk_type

  if chunk_type != CHUNK_TYPE_ASF_HEADER and not processed_asf_header:
    # All chunks of the ASF header has been read, interpret asf_head.
    assert asf_head, 'Missing ASF header.'
    i = 30
    packet_size = 0
    while i + 24 <= len(asf_head):
      guid, size = struct.unpack('<16sQ', asf_head[i : i + 24])
      assert size >= 24
      if size > 65535:
        break
      assert i + size <= len(asf_head), (i + size, size, len(asf_head))
      guid_hex = guid.encode('hex')
      # TODO(pts): Get file size for progress bar etc.
      if guid_hex == GUID_ASF_FILE_PROPERTIES:
        assert size >= 100
        packet_size, = struct.unpack('<L', asf_head[i + 92 : i + 96])
        assert packet_size > 0
        assert packet_size <= 65536, 'Too large packet_size=%d' % packet_size
      i += size
    #assert i == len(asf_head)
    asf_head = ''  # Save memory.
    processed_asf_header = True

  # CHUNK_TYPE_DATA has mms seq in ext_head[5]
  # CHUNK_TYPE_DATA and CHUNK_TYPE_ASF_HEADER have len2 in ext_head[6 : 8]
  chunk_data = f.read(chunk_size)
  pos += len(chunk_data)
  # print 'DUMP size=%d %r' % (len(chunk_data), chunk_data)
  outf.write(chunk_data)
  if chunk_type == CHUNK_TYPE_DATA:
    assert chunk_size <= packet_size, 'Bad chunk_size=%d, packet_size=%d' % (
        chunk_size, packet_size)
    if packet_size > chunk_size:
      outf.write('\0' * (packet_size - chunk_size))  # Padding.
  elif chunk_type == CHUNK_TYPE_ASF_HEADER:
    asf_head += chunk_data
  assert len(chunk_data) == chunk_size
