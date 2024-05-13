unit libssh2;

interface

{$ifdef fpc}
  {$mode delphi}
  uses
    ctypes;
  {$IFDEF WINDOWS}
  const
    libssh2_name = 'libssh2.dll';
  {$ENDIF}
  {$IFDEF LINUX}
  const
    libssh2_name = 'libssh2.so';
  {$ENDIF}
  type
    Uint=cuint;
    ULong=culong;
    Short=cshort;
    PUCHAR=pcuchar;
{$else}

uses
  {$IFDEF WIN32}
    Windows;
  {$ELSE}
  Wintypes, WinProcs;
  {$ENDIF}
  {$ENDIF}

  // Move all constant definitions here
const
  LIBSSH2_CHANNEL_WINDOW_DEFAULT = 65536;

const
  LIBSSH2_CHANNEL_PACKET_DEFAULT = 32768;

const
  LIBSSH2_TERM_WIDTH = 80;

const
  LIBSSH2_TERM_HEIGHT = 24;

const
  LIBSSH2_TERM_WIDTH_PX = 0;

const
  LIBSSH2_TERM_HEIGHT_PX = 0;

const
  SSH_EXTENDED_DATA_STDERR = 1;

const
  LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL = 0;

const
  LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE = 1;

  {+// Error Codes (defined by libssh2)*/ }
const
  LIBSSH2_ERROR_NONE = 0;

const
  LIBSSH2_ERROR_SOCKET_NONE = -1;

const
  LIBSSH2_ERROR_BANNER_NONE = -2;

const
  LIBSSH2_ERROR_BANNER_SEND = -3;

const
  LIBSSH2_ERROR_INVALID_MAC = -4;

const
  LIBSSH2_ERROR_KEX_FAILURE = -5;

const
  LIBSSH2_ERROR_ALLOC = -6;

const
  LIBSSH2_ERROR_SOCKET_SEND = -7;

const
  LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE = -8;

const
  LIBSSH2_ERROR_TIMEOUT = -9;

const
  LIBSSH2_ERROR_HOSTKEY_INIT = -10;

const
  LIBSSH2_ERROR_HOSTKEY_SIGN = -11;

const
  LIBSSH2_ERROR_DECRYPT = -12;

const
  LIBSSH2_ERROR_SOCKET_DISCONNECT = -13;

const
  LIBSSH2_ERROR_PROTO = -14;

const
  LIBSSH2_ERROR_PASSWORD_EXPIRED = -15;

const
  LIBSSH2_ERROR_FILE = -16;

const
  LIBSSH2_ERROR_METHOD_NONE = -17;

const
  LIBSSH2_ERROR_AUTHENTICATION_FAILED = -18;

const
  LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED = LIBSSH2_ERROR_AUTHENTICATION_FAILED;

const
  LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED = -19;

const
  LIBSSH2_ERROR_CHANNEL_OUTOFORDER = -20;

const
  LIBSSH2_ERROR_CHANNEL_FAILURE = -21;

const
  LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED = -22;

const
  LIBSSH2_ERROR_CHANNEL_UNKNOWN = -23;

const
  LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED = -24;

const
  LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED = -25;

const
  LIBSSH2_ERROR_CHANNEL_CLOSED = -26;

const
  LIBSSH2_ERROR_CHANNEL_EOF_SENT = -27;

const
  LIBSSH2_ERROR_SCP_PROTOCOL = -28;

const
  LIBSSH2_ERROR_ZLIB = -29;

const
  LIBSSH2_ERROR_SOCKET_TIMEOUT = -30;

const
  LIBSSH2_ERROR_SFTP_PROTOCOL = -31;

const
  LIBSSH2_ERROR_REQUEST_DENIED = -32;

const
  LIBSSH2_ERROR_METHOD_NOT_SUPPORTED = -33;

const
  LIBSSH2_ERROR_INVAL = -34;

const
  LIBSSH2_ERROR_INVALID_POLL_TYPE = -35;

const
  LIBSSH2_ERROR_PUBLICKEY_PROTOCOL = -36;

const
  LIBSSH2_ERROR_EAGAIN = -37;

const
  LIBSSH2_ERROR_BUFFER_TOO_SMALL = -38;

const
  LIBSSH2_ERROR_BAD_USE = -39;

const
  LIBSSH2_ERROR_COMPRESS = -40;

const
  LIBSSH2_ERROR_OUT_OF_BOUNDARY = -41;

const
  LIBSSH2_ERROR_AGENT_PROTOCOL = -42;

const
  MAX_SSH_PACKET_LEN = 35000;
  MAX_SHA_DIGEST_LEN = 20;

  LIBSSH2_ERROR_BANNER_RECV = -42;
  LIBSSH2_ERROR_CHANNEL_WINDOW_FULL = -43;


  LIBSSH2_SOCKET_UNKNOWN = 1;
  LIBSSH2_SOCKET_CONNECTED = 0;
  LIBSSH2_SOCKET_DISCONNECTED = -1;
  LIBSSH2_DEFAULT_READ_TIMEOUT = 60;

  {$IFDEF WINDOWS}
  LIBSSH2_WINDOWS_UWP = 0;
  {$ENDIF}

  FOPEN_READTEXT = 'rt';
  FOPEN_WRITETEXT = 'wt';
  FOPEN_APPENDTEXT = 'at';

  SSH_MSG_DISCONNECT = 1;
  SSH_MSG_IGNORE = 2;
  SSH_MSG_UNIMPLEMENTED = 3;
  SSH_MSG_DEBUG = 4;
  SSH_MSG_SERVICE_REQUEST = 5;
  SSH_MSG_SERVICE_ACCEPT = 6;
  SSH_MSG_EXT_INFO = 7;
  SSH_MSG_KEXINIT = 20;
  SSH_MSG_NEWKEYS = 21;
  SSH_MSG_KEXDH_INIT = 30;
  SSH_MSG_KEXDH_REPLY = 31;
  SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30;
  SSH_MSG_KEX_DH_GEX_REQUEST = 34;
  SSH_MSG_KEX_DH_GEX_GROUP = 31;
  SSH_MSG_KEX_DH_GEX_INIT = 32;
  SSH_MSG_KEX_DH_GEX_REPLY = 33;
  SSH2_MSG_KEX_ECDH_INIT = 30;
  SSH2_MSG_KEX_ECDH_REPLY = 31;
  SSH_MSG_USERAUTH_REQUEST = 50;
  SSH_MSG_USERAUTH_FAILURE = 51;
  SSH_MSG_USERAUTH_SUCCESS = 52;
  SSH_MSG_USERAUTH_BANNER = 53;
  SSH_MSG_USERAUTH_PK_OK = 60;
  SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;
  SSH_MSG_USERAUTH_INFO_REQUEST = 60;
  SSH_MSG_USERAUTH_INFO_RESPONSE = 61;
  SSH_MSG_GLOBAL_REQUEST = 80;
  SSH_MSG_REQUEST_SUCCESS = 81;
  SSH_MSG_REQUEST_FAILURE = 82;
  SSH_MSG_CHANNEL_OPEN = 90;
  SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
  SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
  SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
  SSH_MSG_CHANNEL_DATA = 94;
  SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
  SSH_MSG_CHANNEL_EOF = 96;
  SSH_MSG_CHANNEL_CLOSE = 97;
  SSH_MSG_CHANNEL_REQUEST = 98;
  SSH_MSG_CHANNEL_SUCCESS = 99;
  SSH_MSG_CHANNEL_FAILURE = 100;
  SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
  SSH_OPEN_CONNECT_FAILED = 2;
  SSH_OPEN_UNKNOWN_CHANNELTYPE = 3;
  SSH_OPEN_RESOURCE_SHORTAGE = 4;

  LIBSSH2_TRACE_TRANS = 1 shl 1;
  LIBSSH2_TRACE_KEX = 1 shl 2;
  LIBSSH2_TRACE_AUTH = 1 shl 3;
  LIBSSH2_TRACE_CONN = 1 shl 4;
  LIBSSH2_TRACE_SCP = 1 shl 5;
  LIBSSH2_TRACE_SFTP = 1 shl 6;
  LIBSSH2_TRACE_ERROR = 1 shl 7;
  LIBSSH2_TRACE_PUBLICKEY = 1 shl 8;
  LIBSSH2_TRACE_SOCKET = 1 shl 9;

  // LIBSSH2_ERROR_SFTP_PROTOCOL = -31;

  LIBSSH2_FXP_INIT = 1;
  LIBSSH2_FXP_VERSION = 2;
  LIBSSH2_FXP_OPEN = 3;
  LIBSSH2_FXP_CLOSE = 4;
  LIBSSH2_FXP_READ = 5;
  LIBSSH2_FXP_WRITE = 6;
  LIBSSH2_FXP_LSTAT = 7;
  LIBSSH2_FXP_FSTAT = 8;
  LIBSSH2_FXP_SETSTAT = 9;
  LIBSSH2_FXP_FSETSTAT = 10;
  LIBSSH2_FXP_OPENDIR = 11;
  LIBSSH2_FXP_READDIR = 12;
  LIBSSH2_FXP_REMOVE = 13;
  LIBSSH2_FXP_MKDIR = 14;
  LIBSSH2_FXP_RMDIR = 15;
  LIBSSH2_FXP_REALPATH = 16;
  LIBSSH2_FXP_STAT = 17;
  LIBSSH2_FXP_RENAME = 18;
  LIBSSH2_FXP_READLINK = 19;
  LIBSSH2_FXP_LINK = 21;
  LIBSSH2_FXP_BLOCK = 22;
  LIBSSH2_FXP_UNBLOCK = 23;

  LIBSSH2_FXP_STATUS = 101;
  LIBSSH2_FXP_HANDLE = 102;
  LIBSSH2_FXP_DATA = 103;
  LIBSSH2_FXP_NAME = 104;
  LIBSSH2_FXP_ATTRS = 105;

  LIBSSH2_FXP_EXTENDED = 200;
  LIBSSH2_FXP_EXTENDED_REPLY = 201;

type
  //  ULong = Cardinal;
  longint = integer;

type
  PLIBSSH2_SFTP = ^LIBSSH2_SFTP;
  LIBSSH2_SFTP = record
  end;

type
  PLIBSSH2_SFTP_HANDLE = ^LIBSSH2_SFTP_HANDLE;

  LIBSSH2_SFTP_HANDLE = record
    sftp: PLIBSSH2_SFTP;
    handle: pansichar;
    handle_len: integer;
    handle_type: integer;
    file_size: uint64;
    packet_size: uint32;
    flags: ULong;
    EOF: integer;
    offset: uint64;
    last_error: integer;
  end;

  PLIBSSH2_SFTP_ATTRIBUTES = ^LIBSSH2_SFTP_ATTRIBUTES;

  LIBSSH2_SFTP_ATTRIBUTES = record
    flags: ULong;
    filesize: uint64;
    uid: ULong;
    gid: ULong;
    permissions: ULong;
    atime: ULong;
    mtime: ULong;
  end;

type
  size_t = cardinal;

  PLIBSSH2_KNOWNHOST = ^LIBSSH2_KNOWNHOST;

  LIBSSH2_KNOWNHOST = record
    magic: uint32;
    node: Pointer;
    Name: pansichar;
    key: pansichar;
    typemask: integer;
  end;

type
  PLIBSSH2_AGENT_PUBLICKEY = ^LIBSSH2_AGENT_PUBLICKEY;

  LIBSSH2_AGENT_PUBLICKEY = record
    magic: uint32;
    node: Pointer;
    blob: pbyte;
    blob_len: size_t;
    comment: pansichar;
  end;


type
  PLIBSSH2_SESSION = ^LIBSSH2_SESSION;
  PLIBSSH2_CHANNEL = ^LIBSSH2_CHANNEL;
  PLIBSSH2_LISTENER = ^LIBSSH2_LISTENER;
  PLIBSSH2_KNOWNHOSTS = ^LIBSSH2_KNOWNHOSTS;
  PLIBSSH2_AGENT = ^LIBSSH2_AGENT;



  // size_t = cardinal;
  ssize_t = int64;
  // PLIBSSH2_KNOWNHOST = ^LIBSSH2_KNOWNHOST;

  (* Add the libssh2_nonblocking_states enumeration here *)
  libssh2_nonblocking_states = (
    libssh2_NB_state_idle = 0,
    libssh2_NB_state_allocated,
    libssh2_NB_state_created,
    libssh2_NB_state_sent,
    libssh2_NB_state_sent1,
    libssh2_NB_state_sent2,
    libssh2_NB_state_sent3,
    libssh2_NB_state_sent4,
    libssh2_NB_state_sent5,
    libssh2_NB_state_sent6,
    libssh2_NB_state_sent7,
    libssh2_NB_state_jump1,
    libssh2_NB_state_jump2,
    libssh2_NB_state_jump3,
    libssh2_NB_state_jump4,
    libssh2_NB_state_jump5
    );


  LIBSSH2_SESSION = record

    sftpInit_state: libssh2_nonblocking_states;
    sftpInit_sftp: PLIBSSH2_SFTP;
    sftpInit_channel: PLIBSSH2_CHANNEL;
    sftpInit_buffer: array[0..8] of byte;
    sftpInit_sent: size_t;
  end;
  LIBSSH2_CHANNEL = record
  end;
  LIBSSH2_LISTENER = record
  end;
  LIBSSH2_KNOWNHOSTS = record
  end;
  LIBSSH2_AGENT = record
  end;

type
  PLIBSSH2_KEX_METHOD = ^_LIBSSH2_KEX_METHOD;

  _LIBSSH2_KEX_METHOD = record
    Name: pansichar;
    exchange_keys: function(session: PLIBSSH2_SESSION;
      key_state: Pointer): integer; cdecl;
    flags: longint;
  end;
  LIBSSH2_KEX_METHOD = _LIBSSH2_KEX_METHOD;

  PLIBSSH2_HOSTKEY_METHOD = ^_LIBSSH2_HOSTKEY_METHOD;

  _LIBSSH2_HOSTKEY_METHOD = record
    Name: pansichar;
    hash_len: longword;
    init: function(session: PLIBSSH2_SESSION; const hostkey_data: pbyte;
      hostkey_data_len: size_t; var abstract: Pointer): integer; cdecl;
    initPEM: function(session: PLIBSSH2_SESSION; const privkeyfile: pansichar;
      const passphrase: pbyte; var abstract: Pointer): integer; cdecl;
    initPEMFromMemory: function(session: PLIBSSH2_SESSION;
      const privkeyfiledata: pansichar; privkeyfiledata_len: size_t;
      const passphrase: pbyte; var abstract: Pointer): integer; cdecl;
    sig_verify: function(session: PLIBSSH2_SESSION; const sig: pbyte;
      sig_len: size_t; const m: pbyte; m_len: size_t;
      var abstract: Pointer): integer; cdecl;
    signv: function(session: PLIBSSH2_SESSION; var signature: pbyte;
      var signature_len: size_t; veccount: integer; const datavec: Pointer;
      var abstract: Pointer): integer; cdecl;
    encrypt: function(session: PLIBSSH2_SESSION; var dst: pbyte;
      var dst_len: size_t; const src: pbyte; src_len: size_t;
      var abstract: Pointer): integer; cdecl;
    dtor: function(session: PLIBSSH2_SESSION; var abstract: Pointer): integer; cdecl;
  end;
  LIBSSH2_HOSTKEY_METHOD = _LIBSSH2_HOSTKEY_METHOD;

  PLIBSSH2_CRYPT_METHOD = ^_LIBSSH2_CRYPT_METHOD;

  _LIBSSH2_CRYPT_METHOD = record
    Name: pansichar;
    pem_annotation: pansichar;
    blocksize: integer;
    iv_len: integer;
    secret_len: integer;
    flags: longint;
    init: function(session: PLIBSSH2_SESSION; const method: PLIBSSH2_CRYPT_METHOD;
      iv: pbyte; var free_iv: integer; secret: pbyte; var free_secret: integer;
      encrypt: integer; var abstract: Pointer): integer; cdecl;
    crypt: function(session: PLIBSSH2_SESSION; var block: pbyte;
      blocksize: size_t; var abstract: Pointer; firstlast: integer): integer; cdecl;
    dtor: function(session: PLIBSSH2_SESSION; var abstract: Pointer): integer; cdecl;
    algo: function(method: PLIBSSH2_CRYPT_METHOD): integer; cdecl;
  end;
  LIBSSH2_CRYPT_METHOD = _LIBSSH2_CRYPT_METHOD;

type



  PLIBSSH2_POLLFD = ^_LIBSSH2_POLLFD;

  _LIBSSH2_POLLFD = record
    _type: byte;
    socket: integer;
    channel: PLIBSSH2_CHANNEL;
    listener: PLIBSSH2_LISTENER;
  end {fd};
  LIBSSH2_POLLFD = _LIBSSH2_POLLFD;



  LIBSSH2_ALLOC_FUNC = function(Count: size_t; abstract: Pointer): Pointer; cdecl;
  LIBSSH2_FREE_FUNC = procedure(ptr: Pointer; abstract: Pointer); cdecl;
  LIBSSH2_REALLOC_FUNC = function(ptr: Pointer; Count: size_t;
    abstract: Pointer): Pointer; cdecl;

  PLIBSSH2_USERAUTH_KBDINT_PROMPT = ^LIBSSH2_USERAUTH_KBDINT_PROMPT;

  LIBSSH2_USERAUTH_KBDINT_PROMPT = record
    Text: pansichar;
    length: size_t;
    echo: byte;
  end;

  PLIBSSH2_USERAUTH_KBDINT_RESPONSE = ^LIBSSH2_USERAUTH_KBDINT_RESPONSE;

  LIBSSH2_USERAUTH_KBDINT_RESPONSE = record
    Text: pansichar;
    length: size_t;
  end;

  LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC = function(session: PLIBSSH2_SESSION;
    var sig: pbyte; var sig_len: size_t; const Data: pbyte; data_len: size_t;
    abstract: Pointer): integer; cdecl;

  LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC = procedure(const Name: pansichar;
    name_len: integer; const instruction: pansichar; instruction_len: integer;
    num_prompts: integer; const prompts: PLIBSSH2_USERAUTH_KBDINT_PROMPT;
    var responses: LIBSSH2_USERAUTH_KBDINT_RESPONSE; abstract: Pointer); cdecl;

  LIBSSH2_IGNORE_FUNC = procedure(session: PLIBSSH2_SESSION;
    const message: pansichar; message_len: integer; abstract: Pointer); cdecl;

  LIBSSH2_DEBUG_FUNC = procedure(session: PLIBSSH2_SESSION;
    always_display: integer; const message: pansichar; message_len: integer;
    const language: pansichar; language_len: integer; abstract: Pointer); cdecl;

  LIBSSH2_DISCONNECT_FUNC = procedure(session: PLIBSSH2_SESSION;
    reason: integer; const message: pansichar; message_len: integer;
    const language: pansichar; language_len: integer; abstract: Pointer); cdecl;

  LIBSSH2_PASSWD_CHANGEREQ_FUNC = procedure(session: PLIBSSH2_SESSION;
    var newpw: pansichar; var newpw_len: integer; abstract: Pointer); cdecl;

  LIBSSH2_MACERROR_FUNC = function(session: PLIBSSH2_SESSION;
    const packet: pansichar; packet_len: integer; abstract: Pointer): integer; cdecl;

  LIBSSH2_X11_OPEN_FUNC = procedure(session: PLIBSSH2_SESSION;
    channel: PLIBSSH2_CHANNEL; const shost: pansichar; sport: integer;
    abstract: Pointer); cdecl;

  LIBSSH2_CHANNEL_CLOSE_FUNC = procedure(session: PLIBSSH2_SESSION;
    var session_abstract: Pointer; channel: PLIBSSH2_CHANNEL;
    var channel_abstract: Pointer); cdecl;


function libssh2_session_disconnect(session: PLIBSSH2_SESSION;
  const description: pansichar): integer;
function libssh2_session_init: PLIBSSH2_SESSION; inline;
function libssh2_userauth_password(session: PLIBSSH2_SESSION;
  const username: pansichar; const password: pansichar): integer;

function _libssh2_snprintf(s: pansichar; maxlen: size_t; const format: pansichar;
  args: array of const): integer;
  cdecl; external libssh2_name Name '_libssh2_snprintf';

type
  PTimeVal = ^TTimeVal;

  TTimeVal = record
    tv_sec: longint;
    tv_usec: longint;
  end;

function _libssh2_gettimeofday(tp: PTimeVal; tzp: Pointer): integer;
  cdecl; external libssh2_name Name '_libssh2_gettimeofday';
function _libssh2_calloc(Count: size_t; size: size_t): Pointer;
  cdecl; external libssh2_name Name '_libssh2_calloc';

function libssh2_init(flags: integer): integer; cdecl;
procedure libssh2_exit; cdecl;
function libssh2_session_init_ex(my_alloc: LIBSSH2_ALLOC_FUNC;
  my_free: LIBSSH2_FREE_FUNC; my_realloc: LIBSSH2_REALLOC_FUNC;
  abstract: Pointer): PLIBSSH2_SESSION; cdecl;
function libssh2_session_abstract(session: PLIBSSH2_SESSION): Pointer; cdecl;
function libssh2_session_callback_set(session: PLIBSSH2_SESSION;
  cbtype: integer; callback: Pointer): Pointer; cdecl;
function libssh2_banner_set(session: PLIBSSH2_SESSION;
  const banner: pansichar): integer; cdecl;
function libssh2_session_startup(session: PLIBSSH2_SESSION;
  sock: integer): integer; cdecl;
function libssh2_session_disconnect_ex(session: PLIBSSH2_SESSION;
  reason: integer; const description: pansichar; const lang: pansichar): integer; cdecl;
function libssh2_session_free(session: PLIBSSH2_SESSION): integer; cdecl;
function libssh2_hostkey_hash(session: PLIBSSH2_SESSION;
  hash_type: integer): pansichar; cdecl;
function libssh2_session_hostkey(session: PLIBSSH2_SESSION; var len: size_t;
  var _type: integer): pansichar; cdecl;
function libssh2_session_method_pref(session: PLIBSSH2_SESSION;
  method_type: integer; const prefs: pansichar): integer; cdecl;
function libssh2_session_methods(session: PLIBSSH2_SESSION;
  method_type: integer): pansichar; cdecl;
function libssh2_session_last_error(session: PLIBSSH2_SESSION;
  var errmsg: pansichar; var errmsg_len: integer; want_buf: integer): integer; cdecl;
function libssh2_session_last_errno(session: PLIBSSH2_SESSION): integer; cdecl;
function libssh2_session_block_directions(session: PLIBSSH2_SESSION): integer; cdecl;
function libssh2_session_flag(session: PLIBSSH2_SESSION; flag: integer;
  Value: integer): integer; cdecl;
function libssh2_userauth_list(session: PLIBSSH2_SESSION;
  const username: pansichar; username_len: size_t): pansichar; cdecl;
function libssh2_userauth_authenticated(session: PLIBSSH2_SESSION): integer; cdecl;
function libssh2_userauth_password_ex(session: PLIBSSH2_SESSION;
  const username: pansichar; username_len: size_t; const password: pansichar;
  password_len: size_t; passwd_change_cb: LIBSSH2_PASSWD_CHANGEREQ_FUNC): integer; cdecl;

function libssh2_userauth_publickey_fromfile_ex(session: PLIBSSH2_SESSION;
  const username: pansichar; username_len: size_t; const publickey: pansichar;
  const privatekey: pansichar; const passphrase: pansichar): integer; cdecl;
function libssh2_userauth_publickey_fromfile(session: PLIBSSH2_SESSION;
  const username: pansichar; const publickey: pansichar;
  const privatekey: pansichar; const passphrase: pansichar): integer; inline;

const
  SSH_DISCONNECT_BY_APPLICATION = 11;

function libssh2_userauth_hostbased_fromfile_ex(session: PLIBSSH2_SESSION;
  const username: pansichar; username_len: size_t; const publickey: pansichar;
  const privatekey: pansichar; const passphrase: pansichar;
  const hostname: pansichar; hostname_len: size_t; local_username: pansichar;
  local_username_len: size_t): integer; cdecl;
function libssh2_userauth_hostbased_fromfile(session: PLIBSSH2_SESSION;
  const username: pansichar; const publickey: pansichar;
  const privatekey: pansichar; const passphrase: pansichar;
  const hostname: pansichar): integer; inline;

function libssh2_userauth_keyboard_interactive_ex(session: PLIBSSH2_SESSION;
  const username: pansichar; username_len: size_t;
  response_callback: LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC): integer; cdecl;
function libssh2_userauth_keyboard_interactive(session: PLIBSSH2_SESSION;
  const username: pansichar; response_callback: LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC):
  integer; inline;

function libssh2_poll(var fds: LIBSSH2_POLLFD; nfds: uint32;
  timeout: longint): integer; cdecl;

function libssh2_channel_open_ex(session: PLIBSSH2_SESSION;
  const channel_type: pansichar; channel_type_len: size_t; window_size: size_t;
  packet_size: size_t; const message: pansichar;
  message_len: size_t): PLIBSSH2_CHANNEL; cdecl;
function libssh2_channel_open_session(session: PLIBSSH2_SESSION): PLIBSSH2_CHANNEL;
  inline;

function libssh2_channel_direct_tcpip_ex(session: PLIBSSH2_SESSION;
  const host: pansichar; port: integer; const shost: pansichar;
  sport: integer): PLIBSSH2_CHANNEL; cdecl;
function libssh2_channel_direct_tcpip(session: PLIBSSH2_SESSION;
  const host: pansichar; port: integer): PLIBSSH2_CHANNEL; inline;

function libssh2_channel_forward_listen_ex(session: PLIBSSH2_SESSION;
  const host: pansichar; port: integer; var bound_port: integer;
  queue_maxsize: integer): PLIBSSH2_LISTENER; cdecl;
function libssh2_channel_forward_listen(session: PLIBSSH2_SESSION;
  port: integer): PLIBSSH2_LISTENER; inline;

function libssh2_channel_forward_cancel(listener: PLIBSSH2_LISTENER): integer; cdecl;
function libssh2_channel_forward_accept(listener: PLIBSSH2_LISTENER): PLIBSSH2_CHANNEL;
  cdecl;

function libssh2_channel_setenv_ex(channel: PLIBSSH2_CHANNEL;
  const varname: pansichar; varname_len: size_t; const Value: pansichar;
  value_len: size_t): integer; cdecl;
function libssh2_channel_setenv(channel: PLIBSSH2_CHANNEL;
  const varname: pansichar; const Value: pansichar): integer; inline;

function libssh2_channel_request_pty_ex(channel: PLIBSSH2_CHANNEL;
  const term: pansichar; term_len: size_t; const modes: pansichar;
  modes_len: size_t; Width: integer; Height: integer; width_px: integer;
  height_px: integer): integer; cdecl;
function libssh2_channel_request_pty(channel: PLIBSSH2_CHANNEL;
  const term: pansichar): integer; inline;

function libssh2_channel_request_pty_size_ex(channel: PLIBSSH2_CHANNEL;
  Width: integer; Height: integer; width_px: integer;
  height_px: integer): integer; cdecl;
function libssh2_channel_request_pty_size(channel: PLIBSSH2_CHANNEL;
  Width: integer; Height: integer): integer; inline;

function libssh2_channel_x11_req_ex(channel: PLIBSSH2_CHANNEL;
  single_connection: integer; const auth_proto: pansichar;
  const auth_cookie: pansichar; screen_number: integer): integer; cdecl;
function libssh2_channel_x11_req(channel: PLIBSSH2_CHANNEL;
  screen_number: integer): integer; inline;

function libssh2_channel_process_startup(channel: PLIBSSH2_CHANNEL;
  const request: pansichar; request_len: size_t; const message: pansichar;
  message_len: size_t): integer; cdecl;
function libssh2_channel_shell(channel: PLIBSSH2_CHANNEL): integer; inline;
function libssh2_channel_exec(channel: PLIBSSH2_CHANNEL;
  const command: pansichar): integer; inline;
function libssh2_channel_subsystem(channel: PLIBSSH2_CHANNEL;
  const subsystem: pansichar): integer; inline;

function libssh2_channel_read_ex(channel: PLIBSSH2_CHANNEL; stream_id: integer;
  buf: PChar; buflen: size_t): integer; cdecl;
function libssh2_channel_read(channel: PLIBSSH2_CHANNEL; buf: PChar;
  buflen: size_t): integer; inline;
function libssh2_channel_read_stderr(channel: PLIBSSH2_CHANNEL;
  buf: PChar; buflen: size_t): integer; inline;

function libssh2_poll_channel_read(channel: PLIBSSH2_CHANNEL;
  extended: integer): integer; cdecl;

function libssh2_channel_window_read_ex(channel: PLIBSSH2_CHANNEL;
  var read_avail: size_t; var window_size_initial: size_t): uint64; cdecl;
function libssh2_channel_window_read(channel: PLIBSSH2_CHANNEL): uint64; inline;

function libssh2_channel_receive_window_adjust(channel: PLIBSSH2_CHANNEL;
  adjustment: longint; force: byte): longint; cdecl;
function libssh2_channel_receive_window_adjust2(channel: PLIBSSH2_CHANNEL;
  adjustment: longint; force: byte; var storewindow: uint64): integer; cdecl;

function libssh2_channel_write_ex(channel: PLIBSSH2_CHANNEL;
  stream_id: integer; const buf: PChar; buflen: size_t): integer; cdecl;
function libssh2_channel_write(channel: PLIBSSH2_CHANNEL; const buf: PChar;
  buflen: size_t): integer; inline;

function libssh2_channel_write_stderr(channel: PLIBSSH2_CHANNEL;
  const buf: PChar; buflen: size_t): integer; inline;

function libssh2_channel_window_write_ex(channel: PLIBSSH2_CHANNEL;
  window_size_initial: PCardinal): uint64; cdecl;
function libssh2_channel_window_write(channel: PLIBSSH2_CHANNEL): uint64; inline;

procedure libssh2_session_set_blocking(session: PLIBSSH2_SESSION;
  blocking: integer); cdecl;
function libssh2_session_get_blocking(session: PLIBSSH2_SESSION): integer; cdecl;

procedure libssh2_channel_set_blocking(channel: PLIBSSH2_CHANNEL;
  blocking: integer); cdecl;

procedure libssh2_channel_handle_extended_data(channel: PLIBSSH2_CHANNEL;
  ignore_mode: integer); cdecl;
procedure libssh2_channel_ignore_extended_data(channel: PLIBSSH2_CHANNEL;
  ignore: integer); inline;

function libssh2_channel_handle_extended_data2(channel: PLIBSSH2_CHANNEL;
  ignore_mode: integer): integer; cdecl;

function libssh2_channel_flush_ex(channel: PLIBSSH2_CHANNEL;
  streamid: integer): integer; cdecl;
function libssh2_channel_flush(channel: PLIBSSH2_CHANNEL): integer; inline;
function libssh2_channel_flush_stderr(channel: PLIBSSH2_CHANNEL): integer; inline;

function libssh2_channel_get_exit_status(channel: PLIBSSH2_CHANNEL): integer; cdecl;
function libssh2_channel_send_eof(channel: PLIBSSH2_CHANNEL): integer; cdecl;
function libssh2_channel_eof(channel: PLIBSSH2_CHANNEL): integer; cdecl;
function libssh2_channel_wait_eof(channel: PLIBSSH2_CHANNEL): integer; cdecl;
function libssh2_channel_close(channel: PLIBSSH2_CHANNEL): integer; cdecl;
function libssh2_channel_wait_closed(channel: PLIBSSH2_CHANNEL): integer; cdecl;
function libssh2_channel_free(channel: PLIBSSH2_CHANNEL): integer; cdecl;

type
  Pstruct_stat = ^struct_stat;

  struct_stat = record
    st_dev: uint32;
    st_ino: word;
    st_mode: word;
    st_nlink: int16;
    st_uid: int16;
    st_gid: int16;
    st_rdev: uint32;
    st_size: int64;
    st_atime: int64;
    st_mtime: int64;
    st_ctime: int64;
  end;

function libssh2_scp_recv(session: PLIBSSH2_SESSION; const path: pansichar;
  var sb: struct_stat): PLIBSSH2_CHANNEL; cdecl;

function libssh2_scp_send_ex(session: PLIBSSH2_SESSION; const path: pansichar;
  mode: integer; size: size_t; mtime: longint; atime: longint): PLIBSSH2_CHANNEL; cdecl;
function libssh2_scp_send64(session: PLIBSSH2_SESSION; const path: pansichar;
  mode: integer; size: int64; mtime: longint; atime: longint): PLIBSSH2_CHANNEL; cdecl;
function libssh2_scp_send(session: PLIBSSH2_SESSION; const path: pansichar;
  mode: integer; size: size_t): PLIBSSH2_CHANNEL; inline;

function libssh2_base64_decode(session: PLIBSSH2_SESSION; var dest: pansichar;
  var dest_len: uint32; const src: pansichar; src_len: uint32): integer; cdecl;

function libssh2_version(req_version_num: integer): pansichar; cdecl;

function libssh2_sftp_init(session: PLIBSSH2_SESSION): PLIBSSH2_SFTP;
  cdecl; external libssh2_name;

function libssh2_sftp_shutdown(sftp: PLIBSSH2_SFTP): longint;
  cdecl; external libssh2_name;

function libssh2_sftp_last_error(sftp: PLIBSSH2_SFTP): ULong; cdecl;
  external libssh2_name;

function libssh2_sftp_get_channel(sftp: PLIBSSH2_SFTP): PLIBSSH2_CHANNEL;
  cdecl; external libssh2_name;

function libssh2_sftp_open_ex(sftp: PLIBSSH2_SFTP; const filename: PAnsiChar;
  filename_len: size_t; flags: ULong; mode: LongInt; open_type: Integer): PLIBSSH2_SFTP_HANDLE; cdecl; external libssh2_name;


function libssh2_sftp_read(handle: PLIBSSH2_SFTP_HANDLE; buf: pbyte;
  buflen: size_t): ssize_t; cdecl; external libssh2_name;

function libssh2_sftp_readdir_ex(handle: PLIBSSH2_SFTP_HANDLE;
  var buffer: pansichar; buffer_maxlen: size_t; var longentry: pansichar;
  longentry_maxlen: size_t; var attrs: LIBSSH2_SFTP_ATTRIBUTES): integer;
  cdecl; external libssh2_name;


function libssh2_sftp_write(handle: PLIBSSH2_SFTP_HANDLE; const buffer: pbyte;
  Count: size_t): ssize_t; cdecl; external libssh2_name;

function libssh2_sftp_close_handle(handle: PLIBSSH2_SFTP_HANDLE): integer;
  cdecl; external libssh2_name;


function libssh2_knownhost_init(session: PLIBSSH2_SESSION): PLIBSSH2_KNOWNHOSTS; cdecl;
function libssh2_knownhost_add(hosts: PLIBSSH2_KNOWNHOSTS;
  host, salt, key: pansichar; keylen: size_t; typemask: integer;
  var store: PLIBSSH2_KNOWNHOST): integer; cdecl;
function libssh2_knownhost_addc(hosts: PLIBSSH2_KNOWNHOSTS;
  host, salt, key: pansichar; keylen: size_t; comment: pansichar;
  commentlen: size_t; typemask: integer; var store: PLIBSSH2_KNOWNHOST): integer; cdecl;
function libssh2_knownhost_check(hosts: PLIBSSH2_KNOWNHOSTS;
  host, key: pansichar; keylen: size_t; typemask: integer;
  var knownhost: PLIBSSH2_KNOWNHOST): integer; cdecl;
function libssh2_knownhost_checkp(hosts: PLIBSSH2_KNOWNHOSTS;
  const host: pansichar; port: integer; const key: pansichar;
  keylen: size_t; typemask: integer; var knownhost: PLIBSSH2_KNOWNHOST): integer; cdecl;
function libssh2_knownhost_del(hosts: PLIBSSH2_KNOWNHOSTS;
  entry: PLIBSSH2_KNOWNHOST): integer; cdecl;
procedure libssh2_knownhost_free(hosts: PLIBSSH2_KNOWNHOSTS); cdecl;
function libssh2_knownhost_readline(hosts: PLIBSSH2_KNOWNHOSTS;
  const line: pansichar; len: size_t; _type: integer): integer; cdecl;
function libssh2_knownhost_readfile(hosts: PLIBSSH2_KNOWNHOSTS;
  const filename: pansichar; _type: integer): integer; cdecl;
function libssh2_knownhost_writeline(hosts: PLIBSSH2_KNOWNHOSTS;
  known: PLIBSSH2_KNOWNHOST; buffer: pansichar; buflen: size_t;
  var outlen: size_t; _type: integer): integer; cdecl;
function libssh2_knownhost_writefile(hosts: PLIBSSH2_KNOWNHOSTS;
  const filename: pansichar; _type: integer): integer; cdecl;
function libssh2_knownhost_get(hosts: PLIBSSH2_KNOWNHOSTS;
  var store: PLIBSSH2_KNOWNHOST; prev: PLIBSSH2_KNOWNHOST): integer; cdecl;

function libssh2_agent_init(session: PLIBSSH2_SESSION): PLIBSSH2_AGENT; cdecl;
function libssh2_agent_connect(agent: PLIBSSH2_AGENT): integer; cdecl;
function libssh2_agent_list_identities(agent: PLIBSSH2_AGENT): integer; cdecl;
function libssh2_agent_get_identity(agent: PLIBSSH2_AGENT;
  var store: PLIBSSH2_AGENT_PUBLICKEY; prev: PLIBSSH2_AGENT_PUBLICKEY): integer; cdecl;
function libssh2_agent_userauth(agent: PLIBSSH2_AGENT; const username: pansichar;
  identity: PLIBSSH2_AGENT_PUBLICKEY): integer; cdecl;
function libssh2_agent_disconnect(agent: PLIBSSH2_AGENT): integer; cdecl;
procedure libssh2_agent_free(agent: PLIBSSH2_AGENT); cdecl;

procedure libssh2_keepalive_config(session: PLIBSSH2_SESSION;
  want_reply: integer; interval: cardinal); cdecl;
function libssh2_keepalive_send(session: PLIBSSH2_SESSION;
  var seconds_to_next: integer): integer; cdecl;

function libssh2_trace(session: PLIBSSH2_SESSION; bitmask: integer): integer; cdecl;

type
  LIBSSH2_TRACE_HANDLER_FUNC = procedure(session: PLIBSSH2_SESSION;
    context: Pointer; const Data: pansichar; length: size_t); cdecl;

function libssh2_trace_sethandler(session: PLIBSSH2_SESSION; context: Pointer;
  callback: LIBSSH2_TRACE_HANDLER_FUNC): integer; cdecl;

implementation

function libssh2_channel_window_write(channel: PLIBSSH2_CHANNEL): uint64; inline;
var
  I: longword;
begin
  I := 0;
  Result := libssh2_channel_window_write_ex(channel, PCardinal(@I));
end;


function libssh2_channel_write(channel: PLIBSSH2_CHANNEL; const buf: PChar;
  buflen: longword): integer; inline;
begin
  Result := libssh2_channel_write_ex(channel, 0, buf, buflen);
end;

function libssh2_session_disconnect(session: PLIBSSH2_SESSION;
  const description: pansichar): integer;
begin
  Result := libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION,
    description, '');
end;

function libssh2_session_init: PLIBSSH2_SESSION; inline;
var
  P1: LIBSSH2_ALLOC_FUNC;
  P2: LIBSSH2_REALLOC_FUNC;
  P3: LIBSSH2_FREE_FUNC;
  P4: Pointer;
begin
  P1 := nil;
  P2 := nil;
  P3 := nil;
  P4 := nil;
  Result := libssh2_session_init_ex(P1, P3, P2, P4);
end;

function libssh2_userauth_password(session: PLIBSSH2_SESSION;
  const username: pansichar; const password: pansichar): integer;
var
  P: LIBSSH2_PASSWD_CHANGEREQ_FUNC;
begin
  P := nil;
  Result := libssh2_userauth_password_ex(session, username, Length(username),
    password, Length(password), P);
end;

function libssh2_init; external libssh2_name;
procedure libssh2_exit; external libssh2_name;
function libssh2_session_init_ex; external libssh2_name;
function libssh2_session_abstract; external libssh2_name;
function libssh2_session_callback_set; external libssh2_name;
function libssh2_banner_set; external libssh2_name;
function libssh2_session_startup; external libssh2_name;
function libssh2_session_disconnect_ex; external libssh2_name;
function libssh2_session_free; external libssh2_name;
function libssh2_hostkey_hash; external libssh2_name;
function libssh2_session_hostkey; external libssh2_name;
function libssh2_session_method_pref; external libssh2_name;
function libssh2_session_methods; external libssh2_name;
function libssh2_session_last_error; external libssh2_name;
function libssh2_session_last_errno; external libssh2_name;
function libssh2_session_block_directions; external libssh2_name;
function libssh2_session_flag; external libssh2_name;
function libssh2_userauth_list; external libssh2_name;
function libssh2_userauth_authenticated; external libssh2_name;
function libssh2_userauth_password_ex; external libssh2_name;
function libssh2_userauth_publickey_fromfile_ex; external libssh2_name;
function libssh2_userauth_hostbased_fromfile_ex; external libssh2_name;
function libssh2_userauth_keyboard_interactive_ex; external libssh2_name;
function libssh2_poll; external libssh2_name;
function libssh2_channel_open_ex; external libssh2_name;
function libssh2_channel_direct_tcpip_ex; external libssh2_name;
function libssh2_channel_forward_listen_ex; external libssh2_name;
function libssh2_channel_forward_cancel; external libssh2_name;
function libssh2_channel_forward_accept; external libssh2_name;
function libssh2_channel_setenv_ex; external libssh2_name;
function libssh2_channel_request_pty_ex; external libssh2_name;
function libssh2_channel_request_pty_size_ex; external libssh2_name;
function libssh2_channel_x11_req_ex; external libssh2_name;
function libssh2_channel_process_startup; external libssh2_name;

function libssh2_channel_read_ex; external libssh2_name;
function libssh2_poll_channel_read; external libssh2_name;
function libssh2_channel_window_read_ex; external libssh2_name;
function libssh2_channel_receive_window_adjust; external libssh2_name;
function libssh2_channel_receive_window_adjust2; external libssh2_name;

function libssh2_channel_write_ex; external libssh2_name;
function libssh2_channel_window_write_ex; external libssh2_name;

function libssh2_channel_write_stderr; external libssh2_name;

procedure libssh2_session_set_blocking; external libssh2_name;
function libssh2_session_get_blocking; external libssh2_name;
procedure libssh2_channel_set_blocking; external libssh2_name;
procedure libssh2_channel_handle_extended_data; external libssh2_name;
function libssh2_channel_handle_extended_data2; external libssh2_name;
function libssh2_channel_flush_ex; external libssh2_name;
function libssh2_channel_get_exit_status; external libssh2_name;
function libssh2_channel_send_eof; external libssh2_name;
function libssh2_channel_eof; external libssh2_name;
function libssh2_channel_wait_eof; external libssh2_name;
function libssh2_channel_close; external libssh2_name;
function libssh2_channel_wait_closed; external libssh2_name;
function libssh2_channel_free; external libssh2_name;
function libssh2_scp_recv; external libssh2_name;
function libssh2_scp_send_ex; external libssh2_name;
function libssh2_scp_send64; external libssh2_name;
function libssh2_base64_decode; external libssh2_name;
function libssh2_version; external libssh2_name;
function libssh2_knownhost_init; external libssh2_name;
function libssh2_knownhost_add; external libssh2_name;
function libssh2_knownhost_addc; external libssh2_name;
function libssh2_knownhost_check; external libssh2_name;
function libssh2_knownhost_checkp; external libssh2_name;
function libssh2_knownhost_del; external libssh2_name;
procedure libssh2_knownhost_free; external libssh2_name;
function libssh2_knownhost_readline; external libssh2_name;
function libssh2_knownhost_readfile; external libssh2_name;
function libssh2_knownhost_writeline; external libssh2_name;
function libssh2_knownhost_writefile; external libssh2_name;
function libssh2_knownhost_get; external libssh2_name;
function libssh2_agent_init; external libssh2_name;
function libssh2_agent_connect; external libssh2_name;
function libssh2_agent_list_identities; external libssh2_name;
function libssh2_agent_get_identity; external libssh2_name;
function libssh2_agent_userauth; external libssh2_name;
function libssh2_agent_disconnect; external libssh2_name;
procedure libssh2_agent_free; external libssh2_name;
procedure libssh2_keepalive_config; external libssh2_name;
function libssh2_keepalive_send; external libssh2_name;
function libssh2_trace; external libssh2_name;
function libssh2_trace_sethandler; external libssh2_name;

function libssh2_userauth_publickey_fromfile(session: PLIBSSH2_SESSION;
  const username: pansichar; const publickey: pansichar;
  const privatekey: pansichar; const passphrase: pansichar): integer;
begin
  Result := libssh2_userauth_publickey_fromfile_ex(session, username,
    Length(username), publickey, privatekey, passphrase);
end;

function libssh2_userauth_hostbased_fromfile(session: PLIBSSH2_SESSION;
  const username: pansichar; const publickey: pansichar;
  const privatekey: pansichar; const passphrase: pansichar;
  const hostname: pansichar): integer;
begin
  Result := libssh2_userauth_hostbased_fromfile_ex(session, username,
    Length(username), publickey, privatekey, passphrase, hostname,
    Length(hostname), username, Length(username));
end;

function libssh2_userauth_keyboard_interactive(session: PLIBSSH2_SESSION;
  const username: pansichar;
  response_callback: LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC): integer;
begin
  Result := libssh2_userauth_keyboard_interactive_ex(session, username,
    Length(username), response_callback);
end;

function libssh2_channel_open_session(session: PLIBSSH2_SESSION): PLIBSSH2_CHANNEL;
begin
  Result := libssh2_channel_open_ex(session, 'session', Length('session'),
    LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT, nil, 0);
end;

function libssh2_channel_direct_tcpip(session: PLIBSSH2_SESSION;
  const host: pansichar; port: integer): PLIBSSH2_CHANNEL;
begin
  Result := libssh2_channel_direct_tcpip_ex(session, host, port, '127.0.0.1', 22);
end;

function libssh2_channel_forward_listen(session: PLIBSSH2_SESSION;
  port: integer): PLIBSSH2_LISTENER;
var
  bound_port: integer;
begin
  bound_port := 0;
  Result := libssh2_channel_forward_listen_ex(session, nil, port, bound_port, 16);
end;

function libssh2_channel_setenv(channel: PLIBSSH2_CHANNEL;
  const varname: pansichar; const Value: pansichar): integer;
begin
  Result := libssh2_channel_setenv_ex(channel, varname, Length(varname),
    Value, Length(Value));
end;

function libssh2_channel_request_pty(channel: PLIBSSH2_CHANNEL;
  const term: pansichar): integer;
begin
  Result := libssh2_channel_request_pty_ex(channel, term, Length(term),
    nil, 0, LIBSSH2_TERM_WIDTH, LIBSSH2_TERM_HEIGHT, LIBSSH2_TERM_WIDTH_PX,
    LIBSSH2_TERM_HEIGHT_PX);
end;

function libssh2_channel_request_pty_size(channel: PLIBSSH2_CHANNEL;
  Width: integer; Height: integer): integer;
begin
  Result := libssh2_channel_request_pty_size_ex(channel, Width, Height, 0, 0);
end;

function libssh2_channel_x11_req(channel: PLIBSSH2_CHANNEL;
  screen_number: integer): integer;
begin
  Result := libssh2_channel_x11_req_ex(channel, 0, nil, nil, screen_number);
end;

function libssh2_channel_shell(channel: PLIBSSH2_CHANNEL): integer;
begin
  Result := libssh2_channel_process_startup(channel, 'shell', Length('shell'), nil, 0);
end;

function libssh2_channel_exec(channel: PLIBSSH2_CHANNEL;
  const command: pansichar): integer;
begin
  Result := libssh2_channel_process_startup(channel, 'exec', Length('exec'),
    command, Length(command));
end;

function libssh2_channel_subsystem(channel: PLIBSSH2_CHANNEL;
  const subsystem: pansichar): integer;
begin
  Result := libssh2_channel_process_startup(channel, 'subsystem',
    Length('subsystem'), subsystem, Length(subsystem));
end;

function libssh2_channel_read(channel: PLIBSSH2_CHANNEL; buf: PChar;
  buflen: size_t): integer;
begin
  Result := libssh2_channel_read_ex(channel, 0, buf, buflen);
end;

function libssh2_channel_read_stderr(channel: PLIBSSH2_CHANNEL; buf: PChar;
  buflen: size_t): integer;
begin
  Result := libssh2_channel_read_ex(channel, SSH_EXTENDED_DATA_STDERR, buf, buflen);
end;

function libssh2_channel_window_read(channel: PLIBSSH2_CHANNEL): uint64;
var
  read_avail, window_size_initial: size_t;
begin
  read_avail := 0;
  window_size_initial := 0;
  Result := libssh2_channel_window_read_ex(channel, read_avail, window_size_initial);
end;

procedure libssh2_channel_ignore_extended_data(channel: PLIBSSH2_CHANNEL;
  ignore: integer);
var
  ignore_mode: integer;
begin
  if ignore <> 0 then
    ignore_mode := LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE
  else
    ignore_mode := LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL;
  libssh2_channel_handle_extended_data(channel, ignore_mode);
end;

function libssh2_channel_flush(channel: PLIBSSH2_CHANNEL): integer;
begin
  Result := libssh2_channel_flush_ex(channel, 0);
end;

function libssh2_channel_flush_stderr(channel: PLIBSSH2_CHANNEL): integer;
begin
  Result := libssh2_channel_flush_ex(channel, SSH_EXTENDED_DATA_STDERR);
end;

function libssh2_scp_send(session: PLIBSSH2_SESSION; const path: pansichar;
  mode: integer; size: size_t): PLIBSSH2_CHANNEL;
begin
  Result := libssh2_scp_send_ex(session, path, mode, size, 0, 0);
end;

end.
