const MAX_TPM2_IO_BUFF_SIZE {.intdefine.} = 4096

type
  SerializationDefect* = Defect
  StaticByteBuffer* = ref object
    wrptr*, rdptr*: uint
    buff*: array[0..MAX_TPM2_IO_BUFF_SIZE, uint8]

proc writeBytes*(sbuff: StaticByteBuffer, bytes: seq[uint8]) =
  if sbuff.wrptr + bytes.len.uint > sbuff.buff.len.uint: 
    raise newException(
      SerializationDefect,
      "buffer length not sufficient for writing further bytes! " &
      $(sbuff.wrptr + bytes.len.uint) & " > " & $sbuff.buff.len
    )

  let 
    r1 = sbuff.wrptr.int
    r2 = sbuff.wrptr.int + bytes.len-1

  var i = 0
  
  for bufPos in r1..r2:
    sbuff.buff[bufPos.uint8] = bytes[i]
    inc i

  sbuff.wrptr = bytes.len.uint

proc readBytes*(sbuff: StaticByteBuffer, size: uint): seq[uint8] =
  if sbuff.rdptr.uint + size.uint > sbuff.wrptr:
    raise newException(
      SerializationDefect,
      "buffer length not sufficient for reading further bytes! " &
      $(sbuff.rdptr + size.uint) & " > " & $sbuff.wrptr
    )

  sbuff.rdptr += size
  sbuff.buff[sbuff.rdptr - size..sbuff.rdptr]

proc toBytes*(sbuff: StaticByteBuffer): seq[uint8] =
  # sbuff.buff[0..sbuff.wrptr]
  @[0'u8]

proc `$`*(sbuff: StaticByteBuffer): string =
  $sbuff.buff

proc newStaticByteBuffer*: StaticByteBuffer =
  var buff: array[0..MAX_TPM2_IO_BUFF_SIZE, uint8]
  StaticByteBuffer(
    wrptr: 0,
    rdptr: 0,
    buff: buff
  )

proc serialize*(u: uint8, buff: var StaticByteBuffer) =
  # Man, I need to implement `writeByte`. I looove allocating seqs for one element.
  buff.writeBytes(
    @[cast[uint8](u)]
  )

proc serialize*(u: uint16, buff: var StaticByteBuffer) =
  # an unsigned 16-bit integer is 2 bytes
  let arr = cast[array[2, uint8]](u)
  var bytes: seq[uint8]

  for x in arr:
    bytes.add x
  
  buff.writeBytes(bytes)

proc serialize*(u: uint32, buff: var StaticByteBuffer) =
  # an unsigned 32-bit integer is 4 bytes
  let arr = cast[array[4, uint8]](u)
  var bytes: seq[uint8]

  for x in arr:
    bytes.add x

  buff.writeBytes(bytes)

proc serialize*(u: uint64, buff: var StaticByteBuffer) =
  # an unsigned 64-bit integer is 8 bytes
  let arr = cast[array[8, uint8]](u)
  var bytes: seq[uint8]

  for x in arr:
    bytes.add x

  buff.writeBytes(bytes)
