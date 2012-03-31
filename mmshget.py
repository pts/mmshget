#! /usr/bin/python2.4

import struct

#define CHUNK_HEADER_LENGTH         4
CHUNK_TYPE_RESET      = 0x4324
CHUNK_TYPE_DATA       = 0x4424
CHUNK_TYPE_END        = 0x4524
CHUNK_TYPE_ASF_HEADER = 0x4824
EXT_HEADER_SIZE = {
  CHUNK_TYPE_RESET      : 4,
  CHUNK_TYPE_DATA       : 8,
  CHUNK_TYPE_END        : 4,
  CHUNK_TYPE_ASF_HEADER : 8,
}

f = open('g2.asf')
while True:
  print '@%d' % f.tell()
  chunk_head = f.read(4)
  assert len(chunk_head) == 4
  chunk_type, chunk_size = struct.unpack('<HH', chunk_head)
  ext_header_size = EXT_HEADER_SIZE.get(chunk_type)
  assert ext_header_size is not None
  if ext_header_size:
    ext_head = f.read(ext_header_size)
    if chunk_type in (CHUNK_TYPE_DATA, CHUNK_TYPE_END):
      print repr(('0x%x' % chunk_type, chunk_head, ext_head))
      seq, = struct.unpack('<L', ext_head[:4])
      print 'seq=%d' % seq
    chunk_size -= ext_header_size
  # CHUNK_TYPE_DATA has mms seq in ext_head[5]
  # CHUNK_TYPE_DATA and CHUNK_TYPE_ASF_HEADER have len2 in ext_head[6 : 8]
  chunk_data = f.read(chunk_size)
  assert len(chunk_data) == chunk_size
