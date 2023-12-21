import ../serialization,
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
  TPM2_PCR_SELECT_MAX: uint = (TPM2_MAX_PCRS + 7'u) / 8'u
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
