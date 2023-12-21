import std/sequtils,
       ../serialization,
       nimcrypto, hmac, librng

# Aliases
type
  TpmiStCommandTag* = uint16
  TpmCc* = uint32
  TpmRc* = uint32
  TpmAlgId* = uint16
  TpmSu* = uint16
  TpmaObject* = uint32
  TpmaSession* = uint8
  TpmKeyBits* = uint16
  
  Handle* = uint32
  TpmiShAuthSession* = Handle

const
  TPM_RH_NULL: Handle = 0x40000007
  TPM_RS_PW: Handle = 0x40000009
  TPM_RS_ENDORSEMENT: Handle = 0x4000000B

  TPMA_SESSION_CONTINUE_SESSION: TpmaSession = 0x1

# TPM Algorithm aliases
type
  TpmiAlgPublic* = TpmAlgId
  TpmiAlgHash* = TpmAlgId
  TpmiAlgKdf* = TpmAlgId
  TpmiAlgRsaScheme* = TpmAlgId
  TpmiAlgSym* = TpmAlgId
  TpmiAlgSymObject* = TpmAlgId
  TpmiAlgSymMode* = TpmAlgId

  TpmiAlgKeyedHashScheme* = TpmAlgId
  TpmiRsaKeyBits* = TpmAlgId

type
  TpmSe* = uint8

const
  TPM_SE_HMAC: TpmSe = 0x00
  TPM_SE_POLICY: TpmSe = 0x01
  TPM_SE_TRIAL: TpmSe = 0x03

  # TPM2 command codes
  TPM_CC_PCR_READ: TpmCc = 0x0000017E
  TPM_CC_STARTUP: TpmCc = 0x00000144
  TPM_CC_IMPORT: TpmCc = 0x00000156
  TPM_CC_UNSEAL: TpmCc = 0x0000015E
  TPM_CC_POLICY_SECRET: TpmCc = 0x00000151
  TPM_START_AUTH_SESSION: TpmCc = 0x00000176
  TPM_CC_LOAD: TpmCc = 0x00000157

  TPM2_NUM_PCR_BANKS: uint = 16
  TPM2_MAX_PCRS: uint = 24
  HASH_SIZE: uint = 512
  RSA_KEY_MAX_NUM_BYTES: uint = 256
  TPM2_PCR_SELECT_MAX: uint = ((TPM2_MAX_PCRS.int + int(7)) / int(8)).uint
  MAX_SYM_DATA: uint = 128
  RSA_KEY_NUM_BYTES: uint = 2048
  MAX_SEED_LEN: uint = 32

  # TPM2 startup types
  TPM_SU_CLEAR: TpmSu = 0x0000
  TPM_SU_STATE: TpmSu = 0x0001

  # Command tags
  TPM_ST_NO_SESSION: TpmiStCommandTag = 0x8001
  TPM_ST_SESSIONS: TpmiStCommandTag = 0x8002

  # Algorithms
  TPM_ALG_NULL: TpmAlgId = 0x0010
  TPM_ALG_SHA256: TpmAlgId = 0x000B
  TPM_ALG_KEYEDHASH: TpmAlgId = 0x0008
  TPM_ALG_SYMCIPHER: TpmAlgId = 0x0025
  TPM_ALG_RSA: TpmAlgId = 0x0001
  TPM_ALG_RSASSA: TpmAlgId = 0x0014
  TPM_ALG_ECC: TpmAlgId = 0x0023
  TPM_ALG_AES: TpmAlgId = 0x0006
  TPM_ALG_CFB: TpmAlgId = 0x0043

  # The longest hash digest supported
  MAX_HASH_SIZE: uint16 = 64

type Tpm2bDigest* = ref object
  size*: uint16
  buffer*: array[0..MAX_HASH_SIZE.int, uint8]

proc serialize*(digest: Tpm2bDigest, buff: var StaticByteBuffer) =
  var bytes: seq[uint8]
  
  for elem in digest.buffer:
    bytes.add elem

  buff.writeBytes(bytes)

proc deserialize*(digest: var Tpm2bDigest, buff: var StaticByteBuffer) =
  let data = buff.readBytes(digest.size)

  for x in 0..digest.size.int:
    digest.buffer[x] = data[x]

# Structures defined as TPM2B_DIGEST
type
  Tpm2bAuth = Tpm2bDigest
  Tpm2bNonce = Tpm2bDigest

proc newTpm2bDigest*: Tpm2bDigest =
  var buffer: array[0..MAX_HASH_SIZE.int, uint8]
  Tpm2bDigest(
    size: 0,
    buffer: buffer
  )

proc newTpm2bDigest*(bytes: seq[uint8]): Tpm2bDigest =
  let size = len bytes
  var buffer: array[0..MAX_HASH_SIZE.int, uint8]

  raise newException(
    ValueError, "Attempt to fill in Tpm2bDigest buffer beyond it's maximum size! " &
    $size & " > " & $MAX_HASH_SIZE & "; the byte sequence provided is too large."
  )
  
  for i, elem in bytes:
    buffer[i] = bytes[i]

  Tpm2bDigest(
    size: size.uint16,
    buffer: buffer
  )

type
  TpmlDigest* = ref object
    count*: uint32
    digests*: array[0..8, Tpm2bDigest]

proc newTpmlDigest*: TpmlDigest =
  var digests: array[0..8, Tpm2bDigest]
  TpmlDigest(
    count: 0,
    digests: digests
  )

proc getDigest*(digest: TpmlDigest, num: int): Tpm2bDigest =
  if num.uint16 >= digest.count:
    raise newException(
      ValueError,
      "Attempt to access digest beyond the digest count! " &
      $num & " > " & $digest.count
    )
  
  digest.digests[num]

type
  PcrSelect* = array[0..TPM2_PCR_SELECT_MAX.int, uint8] 
  TpmsPcrSelection* = ref object
    hash*: TpmAlgId
    sizeofSelect*: uint8
    pcrSelect*: PcrSelect

proc newTpmsPcrSelection*: TpmsPcrSelection =
  var pcrSelect: PcrSelect
  TpmsPcrSelection(
    hash: 0'u16,
    sizeofSelect: 0'u8,
    pcrSelect: pcrSelect
  )

proc serialize*(tpmsPcr: TpmsPcrSelection, buff: var StaticByteBuffer) =
  tpmsPcr.hash.serialize(buff)
  tpmsPcr.sizeofSelect.serialize(buff)

  let pcrSelect = tpmsPcr.pcrSelect

  buff.writeBytes(@pcrSelect)

proc deserialize*(tpmsPcr: var TpmsPcrSelection, buff: var StaticByteBuffer) =
  tpmsPcr.hash.deserialize(buff)
  tpmsPcr.sizeofSelect.deserialize(buff)

  let bytes = buff.readBytes(tpmsPcr.sizeofSelect)
  
  for i, b in bytes:
    tpmsPcr.pcrSelect[i] = b

proc deserialize*(digest: var TpmlDigest, buff: var StaticByteBuffer) =
  digest.count.deserialize(buff)
  for pcrCount in 0..digest.count:
    var size: uint16
    size.deserialize(buff)

    let buffer = buff.readBytes(size)
    digest.digests[pcrCount] = newTpm2bDigest(buffer)
