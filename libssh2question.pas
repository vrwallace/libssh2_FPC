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
  const
    libssh2_name = 'libssh2.dll';
{$ENDIF}

type
  libssh2_uint64_t = UInt64;
  libssh2_int64_t = Int64;
  uint32_t = UInt;
  ssize_t = Integer;
  time_t = ULong;

const
  _LIBSSH2_VERSION = '1.2.6';

const
  LIBSSH2_VERSION_MAJOR = 1;
  LIBSSH2_VERSION_MINOR = 2;
  LIBSSH2_VERSION_PATCH = 6;

const
  SHA_DIGEST_LENGTH = 20;
  MD5_DIGEST_LENGTH = 16;
  SHA256_DIGEST_LENGTH = 32;
  SHA512_DIGEST_LENGTH = 64;

const
  LIBSSH2_VERSION_NUM = $010206;
  LIBSSH2_TIMESTAMP = 'Thu Jun 10 08:19:51 UTC 2010';
  LIBSSH2_SSH_BANNER = 'SSH-2.0-libssh2_'  + _LIBSSH2_VERSION;
  LIBSSH2_SSH_DEFAULT_BANNER = LIBSSH2_SSH_BANNER;
  LIBSSH2_SSH_DEFAULT_BANNER_WITH_CRLF = LIBSSH2_SSH_DEFAULT_BANNER + '#13#10';

const
  LIBSSH2_DH_GEX_MINGROUP = 1024;
  LIBSSH2_DH_GEX_OPTGROUP = 1536;
  LIBSSH2_DH_GEX_MAXGROUP = 2048;

const
  LIBSSH2_TERM_WIDTH = 80;
  LIBSSH2_TERM_HEIGHT = 24;
  LIBSSH2_TERM_WIDTH_PX = 0;
  LIBSSH2_TERM_HEIGHT_PX = 0;
  
const
  LIBSSH2_SOCKET_POLL_UDELAY = 250000;
  LIBSSH2_SOCKET_POLL_MAXLOOPS = 120;
  
const
  LIBSSH2_PACKET_MAXCOMP = 32000;
  LIBSSH2_PACKET_MAXDECOMP = 40000;
  LIBSSH2_PACKET_MAXPAYLOAD = 40000;

{const
  LIBSSH2_ALLOC = LIBSSH2_ALLOC_FUNC;
  LIBSSH2_CALLOC = LIBSSH2_CALLOC_FUNC;
  LIBSSH2_REALLOC = LIBSSH2_REALLOC_FUNC;
  LIBSSH2_FREE = LIBSSH2_FREE_FUNC;
  LIBSSH2_IGNORE = LIBSSH2_IGNORE_FUNC;
  LIBSSH2_DEBUG = LIBSSH2_DEBUG_FUNC;
  LIBSSH2_DISCONNECT = LIBSSH2_DISCONNECT_FUNC;
  LIBSSH2_MACERROR = LIBSSH2_MACERROR_FUNC;
  LIBSSH2_X11_OPEN = LIBSSH2_X11_OPEN_FUNC;
  LIBSSH2_AUTHAGENT = LIBSSH2_AUTHAGENT_FUNC;
  LIBSSH2_ADD_IDENTITIES = LIBSSH2_ADD_IDENTITIES_FUNC;
  LIBSSH2_AUTHAGENT_SIGN = LIBSSH2_AUTHAGENT_SIGN_FUNC;
  LIBSSH2_CHANNEL_CLOSE = LIBSSH2_CHANNEL_CLOSE_FUNC;
  LIBSSH2_SEND_FD = LIBSSH2_SEND_FUNC;
  LIBSSH2_RECV_FD = LIBSSH2_RECV_FUNC;
  LIBSSH2_SEND = LIBSSH2_SEND_FD;
  LIBSSH2_RECV = LIBSSH2_RECV_FD;}
  
const  
  LIBSSH2_INIT_NO_CRYPTO = $0001;
  
type
  LIBSSH2_SESSION = record
    // Fields of LIBSSH2_SESSION go here
  end;
  LIBSSH2_CHANNEL = record
    // Fields of LIBSSH2_CHANNEL go here
  end;
  LIBSSH2_LISTENER = record
    // Fields of LIBSSH2_LISTENER go here
  end;
  LIBSSH2_KNOWNHOSTS = record
    // Fields of LIBSSH2_KNOWNHOSTS go here
  end;
  LIBSSH2_AGENT = record
    // Fields of LIBSSH2_AGENT go here
  end;


type
  PLIBSSH2_SESSION = ^LIBSSH2_SESSION;
  PLIBSSH2_CHANNEL = ^LIBSSH2_CHANNEL;
  PLIBSSH2_LISTENER = ^LIBSSH2_LISTENER;
  PLIBSSH2_KNOWNHOSTS = ^LIBSSH2_KNOWNHOSTS;
  PLIBSSH2_AGENT = ^LIBSSH2_AGENT;
  
  LIBSSH2_ALLOC_FUNC = function(count: UINT; abstract: Pointer): Pointer; cdecl;
  LIBSSH2_REALLOC_FUNC = function(ptr: Pointer; count: UINT; abstract: Pointer): Pointer; cdecl;
  LIBSSH2_FREE_FUNC = procedure(ptr: Pointer; abstract: Pointer); cdecl;

  LIBSSH2_PASSWD_CHANGEREQ_FUNC = procedure(session: PLIBSSH2_SESSION;
                                             var newpw: PAnsiChar;
                                             var newpw_len: Integer;
                                             abstract: Pointer); cdecl;
  LIBSSH2_MACERROR_FUNC = function(session: PLIBSSH2_SESSION;
                                    const packet: PAnsiChar;
                                    packet_len: Integer;
                                    abstract: Pointer): Integer; cdecl;
  LIBSSH2_X11_OPEN_FUNC = procedure(session: PLIBSSH2_SESSION;
                                     channel: PLIBSSH2_CHANNEL;
                                     const shost: PAnsiChar;
                                     sport: Integer;
                                     abstract: Pointer); cdecl;
  LIBSSH2_CHANNEL_CLOSE_FUNC = procedure(session: PLIBSSH2_SESSION;
                                          var session_abstract: Pointer;
                                          channel: PLIBSSH2_CHANNEL;
                                          var channel_abstract: Pointer); cdecl;

  LIBSSH2_IGNORE_FUNC = procedure(session: PLIBSSH2_SESSION;
                                   const message: PAnsiChar;
                                   message_len: Integer;
                                   abstract: Pointer); cdecl;

  LIBSSH2_DEBUG_FUNC = procedure(session: PLIBSSH2_SESSION;
                                  always_display: Integer;
                                  const message: PAnsiChar;
                                  message_len: Integer;
                                  const language: PAnsiChar;
                                  language_len: Integer;
                                  abstract: Pointer); cdecl;

  LIBSSH2_DISCONNECT_FUNC = procedure(session: PLIBSSH2_SESSION;
                                       reason: Integer;
                                       const message: PAnsiChar;
                                       message_len: Integer;
                                       const language: PAnsiChar;
                                       language_len: Integer;
                                       abstract: Pointer); cdecl;

   LIBSSH2_SEND_FUNC = function(fd: Integer;
                                const buffer;
                                length: size_t;
                                flags: Integer;
                                abstract: Pointer): ssize_t; cdecl;

  LIBSSH2_RECV_FUNC = function(fd: Integer;
                                CONST buffer;
                                length: size_t;
                                flags: Integer;
                                abstract: Pointer): ssize_t; cdecl;
                                
  LIBSSH2_AUTHAGENT_FUNC = function(channel: PLIBSSH2_CHANNEL;
                                     abstract: Pointer): Integer; cdecl;

  LIBSSH2_ADD_IDENTITIES_FUNC = function(session: PLIBSSH2_SESSION;
                                          const buffer;
                                          const agentPath: PAnsiChar;
                                          abstract: Pointer): Integer; cdecl;

  LIBSSH2_AUTHAGENT_SIGN_FUNC = function(session: PLIBSSH2_SESSION;
                                          const blob;
                                          blen: size_t;
                                          const data;
                                          dlen: size_t;
                                          var sig;
                                          var sigLen: size_t;
                                          const agentPath: PAnsiChar;
                                          abstract: Pointer): Integer; cdecl;
                                          
const  
  LIBSSH2_CALLBACK_IGNORE = 0;
  LIBSSH2_CALLBACK_DEBUG = 1;
  LIBSSH2_CALLBACK_DISCONNECT = 2;
  LIBSSH2_CALLBACK_MACERROR = 3;
  LIBSSH2_CALLBACK_X11 = 4;

const
  LIBSSH2_METHOD_KEX = 0;
  LIBSSH2_METHOD_HOSTKEY = 1;
  LIBSSH2_METHOD_CRYPT_CS = 2;
  LIBSSH2_METHOD_CRYPT_SC = 3;
  LIBSSH2_METHOD_MAC_CS = 4;
  LIBSSH2_METHOD_MAC_SC = 5;
  LIBSSH2_METHOD_COMP_CS = 6;
  LIBSSH2_METHOD_COMP_SC = 7;
  LIBSSH2_METHOD_LANG_CS = 8;
  LIBSSH2_METHOD_LANG_SC = 9;
 
const  
  LIBSSH2_FLAG_SIGPIPE = $00000001;

const  
  LIBSSH2_POLLFD_SOCKET = 1;
  LIBSSH2_POLLFD_CHANNEL = 2;
  LIBSSH2_POLLFD_LISTENER = 3;
  
const  
  LIBSSH2_POLLFD_POLLIN = $0001;
  LIBSSH2_POLLFD_POLLPRI = $0002;
  LIBSSH2_POLLFD_POLLEXT = $0002;
  LIBSSH2_POLLFD_POLLOUT = $0004;
  LIBSSH2_POLLFD_POLLERR = $0008;
  LIBSSH2_POLLFD_POLLHUP = $0010;
  LIBSSH2_POLLFD_SESSION_CLOSED = $0010;
  LIBSSH2_POLLFD_POLLNVAL = $0020;
  LIBSSH2_POLLFD_POLLEX = $0040;
  LIBSSH2_POLLFD_CHANNEL_CLOSED = $0080;
  LIBSSH2_POLLFD_LISTENER_CLOSED = $0080;
  
const  
  HAVE_LIBSSH2_SESSION_BLOCK_DIRECTION = 1;
  LIBSSH2_SESSION_BLOCK_INBOUND = $0001;
  LIBSSH2_SESSION_BLOCK_OUTBOUND = $0002;
  
const  
  LIBSSH2_HOSTKEY_HASH_MD5 = 1;
  LIBSSH2_HOSTKEY_HASH_SHA1 = 2;

const
  LIBSSH2_HOSTKEY_TYPE_UNKNOWN = 0;
  LIBSSH2_HOSTKEY_TYPE_RSA = 1;
  LIBSSH2_HOSTKEY_TYPE_DSS = 2;

const
  SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1;
  SSH_DISCONNECT_PROTOCOL_ERROR = 2;
  SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3;
  SSH_DISCONNECT_RESERVED = 4;
  SSH_DISCONNECT_MAC_ERROR = 5;
  SSH_DISCONNECT_COMPRESSION_ERROR = 6;
  SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7;
  SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8;
  SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9;
  SSH_DISCONNECT_CONNECTION_LOST = 10;
  SSH_DISCONNECT_BY_APPLICATION = 11;
  SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12;
  SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13;
  SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14;
  SSH_DISCONNECT_ILLEGAL_USER_NAME = 15;

const
  LIBSSH2_ERROR_NONE = 0;
  LIBSSH2_ERROR_SOCKET_NONE = -1;
  LIBSSH2_ERROR_BANNER_NONE = -2;
  LIBSSH2_ERROR_BANNER_SEND = -3;
  LIBSSH2_ERROR_INVALID_MAC = -4;
  LIBSSH2_ERROR_KEX_FAILURE = -5;
  LIBSSH2_ERROR_ALLOC = -6;
  LIBSSH2_ERROR_SOCKET_SEND = -7;
  LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE = -8;
  LIBSSH2_ERROR_TIMEOUT = -9;
  LIBSSH2_ERROR_HOSTKEY_INIT = -10;
  LIBSSH2_ERROR_HOSTKEY_SIGN = -11;
  LIBSSH2_ERROR_DECRYPT = -12;
  LIBSSH2_ERROR_SOCKET_DISCONNECT = -13;
  LIBSSH2_ERROR_PROTO = -14;
  LIBSSH2_ERROR_PASSWORD_EXPIRED = -15;
  LIBSSH2_ERROR_FILE = -16;
  LIBSSH2_ERROR_METHOD_NONE = -17;
  LIBSSH2_ERROR_AUTHENTICATION_FAILED = -18;
  LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED = LIBSSH2_ERROR_AUTHENTICATION_FAILED;
  LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED = -19;
  LIBSSH2_ERROR_CHANNEL_OUTOFORDER = -20;
  LIBSSH2_ERROR_CHANNEL_FAILURE = -21;
  LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED = -22;
  LIBSSH2_ERROR_CHANNEL_UNKNOWN = -23;
  LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED = -24;
  LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED = -25;
  LIBSSH2_ERROR_CHANNEL_CLOSED = -26;
  LIBSSH2_ERROR_CHANNEL_EOF_SENT = -27;
  LIBSSH2_ERROR_SCP_PROTOCOL = -28;
  LIBSSH2_ERROR_ZLIB = -29;
  LIBSSH2_ERROR_SOCKET_TIMEOUT = -30;
  LIBSSH2_ERROR_SFTP_PROTOCOL = -31;
  LIBSSH2_ERROR_REQUEST_DENIED = -32;
  LIBSSH2_ERROR_METHOD_NOT_SUPPORTED = -33;
  LIBSSH2_ERROR_INVAL = -34;
  LIBSSH2_ERROR_INVALID_POLL_TYPE = -35;
  LIBSSH2_ERROR_PUBLICKEY_PROTOCOL = -36;
  LIBSSH2_ERROR_EAGAIN = -37;
  LIBSSH2_ERROR_BUFFER_TOO_SMALL = -38;
  LIBSSH2_ERROR_BAD_USE = -39;
  LIBSSH2_ERROR_COMPRESS = -40;
  LIBSSH2_ERROR_OUT_OF_BOUNDARY = -41;
  LIBSSH2_ERROR_AGENT_PROTOCOL = -42;
  
type
  _LIBSSH2_USERAUTH_KBDINT_PROMPT = record
    text: PAnsiChar;
    length: UInt;
    echo: Byte;
  end;
  LIBSSH2_USERAUTH_KBDINT_PROMPT = _LIBSSH2_USERAUTH_KBDINT_PROMPT;
  PLIBSSH2_USERAUTH_KBDINT_PROMPT = ^LIBSSH2_USERAUTH_KBDINT_PROMPT;

  _LIBSSH2_USERAUTH_KBDINT_RESPONSE = record
    text: PAnsiChar;
    length: UInt;
  end;
  LIBSSH2_USERAUTH_KBDINT_RESPONSE = _LIBSSH2_USERAUTH_KBDINT_RESPONSE;
  
  LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC = function(session: PLIBSSH2_SESSION;
                                                   var sig: PByte;
                                                   sig_len: size_t;
                                                   const data: PByte;
                                                   data_len: size_t;
                                                   abstract: Pointer): Integer; cdecl;

  LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC = procedure(const name: PAnsiChar;
                                                     name_len: Integer;
                                                     const instruction: PAnsiChar;
                                                     instruction_len: Integer;
                                                     num_prompts: Integer;
                                                     const prompts: PLIBSSH2_USERAUTH_KBDINT_PROMPT;
                                                     var responses: LIBSSH2_USERAUTH_KBDINT_RESPONSE;
                                                     abstract: Pointer); cdecl;
                                                     
const  
  LIBSSH2_CHANNEL_WINDOW_DEFAULT = 65536;
  LIBSSH2_CHANNEL_PACKET_DEFAULT = 32768;
  LIBSSH2_CHANNEL_MINADJUST = 1024;
  
const  
  LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL = 0;
  LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE = 1;
  LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE = 2;
  
const  
  SSH_EXTENDED_DATA_STDERR = 1;
  
const 
  LIBSSH2CHANNEL_EAGAIN = LIBSSH2_ERROR_EAGAIN;
  
const  
  LIBSSH2_KNOWNHOST_TYPE_MASK = $ffff;
  LIBSSH2_KNOWNHOST_TYPE_PLAIN = 1;
  LIBSSH2_KNOWNHOST_TYPE_SHA1 = 2;
  LIBSSH2_KNOWNHOST_TYPE_CUSTOM = 3;
  
const
  LIBSSH2_KNOWNHOST_KEYENC_MASK = (3 shl 16);
  LIBSSH2_KNOWNHOST_KEYENC_RAW = (1 shl 16);
  LIBSSH2_KNOWNHOST_KEYENC_BASE64 = (2 shl 16);
  
const  
  LIBSSH2_KNOWNHOST_KEY_MASK = (3 shl 18);
  LIBSSH2_KNOWNHOST_KEY_SHIFT = 18;
  LIBSSH2_KNOWNHOST_KEY_RSA1 = (1 shl 18);
  LIBSSH2_KNOWNHOST_KEY_SSHRSA = (2 shl 18);
  LIBSSH2_KNOWNHOST_KEY_SSHDSS = (3 shl 18);
  
const  
  LIBSSH2_KNOWNHOST_CHECK_MATCH = 0;
  LIBSSH2_KNOWNHOST_CHECK_MISMATCH = 1;
  LIBSSH2_KNOWNHOST_CHECK_NOTFOUND = 2;
  LIBSSH2_KNOWNHOST_CHECK_FAILURE = 3;
  
const
  LIBSSH2_KNOWNHOST_FILE_OPENSSH = 1;
  
type  
  PLIBSSH2_KNOWNHOST = ^LIBSSH2_KNOWNHOST;
  LIBSSH2_KNOWNHOST = record
    magic: UInt;
    node: Pointer;
    name: PAnsiChar; 
    key: PAnsiChar;
    typemask: Integer;
  end;
  
const  
  HAVE_LIBSSH2_KNOWNHOST_API = $010101;
  HAVE_LIBSSH2_VERSION_API = $010100;
  
const
  HAVE_LIBSSH2_AGENT_API = $010202;
  
type
  libssh2_agent_publickey = record
    magic: UInt;
    node: Pointer;
    blob: PUCHAR;
    blob_len: SIZE_T;
    comment: PAnsiChar;
  end;
  PLIBSSH2_AGENT_PUBLICKEY = ^libssh2_agent_publickey;
  
type
  Pstruct_stat = ^struct_stat;
  struct_stat = record
    st_dev: UINT;
    st_ino: Word;
    st_mode: Word;
    st_nlink: Short;
    st_uid: Short;
    st_gid: Short;
    st_rdev: UINT;
    st_size: LongInt;
    st_atime: Int64;
    st_mtime: Int64;
    st_ctime: Int64;
  end;
  
type  
  LIBSSH2_TRACE_HANDLER_FUNC = procedure(session: PLIBSSH2_SESSION;
                                          P: Pointer;
                                          const C: PAnsiChar;
                                          S: size_t); cdecl;
  
const
  LIBSSH2_TRACE_TRANS = (1 shl 1);
  LIBSSH2_TRACE_KEX = (1 shl 2);
  LIBSSH2_TRACE_AUTH = (1 shl 3);
  LIBSSH2_TRACE_CONN = (1 shl 4);
  LIBSSH2_TRACE_SCP = (1 shl 5);
  LIBSSH2_TRACE_SFTP = (1shl 6);
  LIBSSH2_TRACE_ERROR = (1 shl 7);
  LIBSSH2_TRACE_PUBLICKEY = (1 shl 8);
  LIBSSH2_TRACE_SOCKET = (1 shl 9);
  
{$ifdef WIN32}
  {$DEFINE LIBSSH2_WINDOWS_UWP}
  {$DEFINE LIBSSH2_WINDOWS}
{$endif}

implementation

function libssh2_init; external libssh2_name;
procedure libssh2_exit; external libssh2_name;
function libssh2_session_init_ex; external libssh2_name;
function libssh2_session_abstract; external libssh2_name;
function libssh2_session_callback_set; external libssh2_name;
function libssh2_banner_set; external libssh2_name;
function libssh2_session_startup; external libssh2_name;
function libssh2_session_disconnect_ex; external libssh2_name;
function libssh2_session_disconnect(session: PLIBSSH2_SESSION; const description: PAnsiChar): Integer;
begin
  Result := libssh2_session_disconnect_ex(session, SSH_DISCONNECT_BY_APPLICATION, description, '');
end;
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
function libssh2_userauth_password(session: PLIBSSH2_SESSION; const username: PAnsiChar; const password: PAnsiChar): Integer;
var
  P: LIBSSH2_PASSWD_CHANGEREQ_FUNC;
begin
  P := nil;
  Result := libssh2_userauth_password_ex(session, username, Length(username), password, Length(password), P)
end;
function libssh2_userauth_publickey_fromfile_ex; external libssh2_name;
function libssh2_userauth_publickey_fromfile(session: PLIBSSH2_SESSION; const username: PAnsiChar; const publickey: PAnsiChar; const privatekey: PAnsiChar; const passphrase: PAnsiChar): Integer;
begin
  Result := libssh2_userauth_publickey_fromfile_ex(session, username, Length(username), publickey, privatekey, passphrase);
end;
function libssh2_userauth_hostbased_fromfile_ex; external libssh2_name;
function libssh2_userauth_hostbased_fromfile(session: PLIBSSH2_SESSION; const username: PAnsiChar; const publickey: PAnsiChar; const privatekey: PAnsiChar; const passphrase: PAnsiChar; const hostname: PAnsiChar): Integer;
begin
  Result := libssh2_userauth_hostbased_fromfile_ex(session, username, Length(username), publickey, privatekey, passphrase, hostname, Length(hostname), username, Length(username));
end;
function libssh2_userauth_keyboard_interactive_ex; external libssh2_name;
function libssh2_userauth_keyboard_interactive(session: PLIBSSH2_SESSION; const username: PAnsiChar; response_callback: LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC): Integer;
begin
  Result := libssh2_userauth_keyboard_interactive_ex(session, username, Length(username), response_callback);
end;
function libssh2_poll; external libssh2_name;
function libssh2_channel_open_ex; external libssh2_name;  
function libssh2_channel_open_session(session: PLIBSSH2_SESSION): PLIBSSH2_CHANNEL;
begin
  Result := libssh2_channel_open_ex(session, 'session', Length('session'), LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT, nil, 0);  
end;
function libssh2_channel_direct_tcpip_ex; external libssh2_name;
function libssh2_channel_direct_tcpip(session: PLIBSSH2_SESSION; const host: PAnsiChar; port: Integer): PLIBSSH2_CHANNEL;
begin
  Result := libssh2_channel_direct_tcpip_ex(session, host, port, '127.0.0.1', 22);
end;
function libssh2_channel_forward_listen_ex; external libssh2_name;
function libssh2_channel_forward_listen(session: PLIBSSH2_SESSION; port: Integer): PLIBSSH2_LISTENER;
var
  I: Integer;
begin
  I := 0;
  Result := libssh2_channel_forward_listen_ex(session, nil, port, I, 16);
end;
function libssh2_channel_forward_cancel; external libssh2_name;
function libssh2_channel_forward_accept; external libssh2_name;
function libssh2_channel_setenv_ex; external libssh2_name;
function libssh2_channel_setenv(channel: PLIBSSH2_CHANNEL; const varname: PAnsiChar; const value: PAnsiChar): Integer;
begin
  Result := libssh2_channel_setenv_ex(channel, varname, Length(varname), value, Length(value));
end;
function libssh2_channel_request_pty_ex; external libssh2_name;
function libssh2_channel_request_pty(channel: PLIBSSH2_CHANNEL; const term: PAnsiChar): Integer;
begin
  Result := libssh2_channel_request_pty_ex(channel, term, Length(term), nil, 0, LIBSSH2_TERM_WIDTH, LIBSSH2_TERM_HEIGHT, LIBSSH2_TERM_WIDTH_PX, LIBSSH2_TERM_HEIGHT_PX);
end;
function libssh2_channel_request_pty_size_ex; external libssh2_name;
function libssh2_channel_request_pty_size(channel: PLIBSSH2_CHANNEL; width: Integer; height: Integer): Integer;
begin
  Result := libssh2_channel_request_pty_size_ex(channel, width, height, 0, 0);
end;
function libssh2_channel_x11_req_ex; external libssh2_name;
function libssh2_channel_x11_req(channel: PLIBSSH2_CHANNEL; screen_number: Integer): Integer;
begin
  Result := libssh2_channel_x11_req_ex(channel, 0, nil, nil, screen_number);
end;
function libssh2_channel_process_startup; external libssh2_name;
function libssh2_channel_shell(channel: PLIBSSH2_CHANNEL): Integer;
begin
  Result := libssh2_channel_process_startup(channel, 'shell', Length('shell'), nil, 0);
end;
function libssh2_channel_exec(channel: PLIBSSH2_CHANNEL; const command: PAnsiChar): Integer;
begin
  Result := libssh2_channel_process_startup(channel, 'exec', Length('exec'), command, Length(command));
end;  
function libssh2_channel_subsystem(channel: PLIBSSH2_CHANNEL; const subsystem: PAnsiChar): Integer;
begin
  Result := libssh2_channel_process_startup(channel, 'subsystem', Length('subsystem'), subsystem, Length(subsystem));
end;
function libssh2_channel_read_ex; external libssh2_name;function libssh2_channel_read(channel: PLIBSSH2_CHANNEL; buf: PAnsiChar; buflen: SIZE_T): Integer;
begin
  Result := libssh2_channel_read_ex(channel, 0, buf, buflen);
end;
function libssh2_channel_read_stderr(channel: PLIBSSH2_CHANNEL; buf: PAnsiChar; buflen: SIZE_T): Integer;
begin
  Result := libssh2_channel_read_ex(channel, SSH_EXTENDED_DATA_STDERR, buf, buflen);
end;

function libssh2_poll_channel_read; external libssh2_name;
function libssh2_channel_window_read_ex; external libssh2_name;
function libssh2_channel_window_read(channel: PLIBSSH2_CHANNEL): ULong;
var
  I: Integer;
begin
  I := 0;
  Result := libssh2_channel_window_read_ex(channel, I, I);
end;
function libssh2_channel_receive_window_adjust; external libssh2_name;
function libssh2_channel_receive_window_adjust2; external libssh2_name;
function libssh2_channel_write_ex; external libssh2_name;
function libssh2_channel_write(channel: PLIBSSH2_CHANNEL; const buf: PAnsiChar; buflen: ULong): Integer;
begin
  Result := libssh2_channel_write_ex(channel, 0, buf, buflen);
end;
function libssh2_channel_write_stderr(channel: PLIBSSH2_CHANNEL; const buf: PAnsiChar; buflen: ULong): Integer;
begin
  Result := libssh2_channel_write_ex(channel, SSH_EXTENDED_DATA_STDERR, buf, buflen);
end;
function libssh2_channel_window_write_ex; external libssh2_name;
function libssh2_channel_window_write(channel: PLIBSSH2_CHANNEL): ULong;
var
  I: Integer;
begin
  I := 0;
  Result := libssh2_channel_window_write_ex(channel, I);
end;
procedure libssh2_session_set_blocking; external libssh2_name;
function libssh2_session_get_blocking; external libssh2_name;
procedure libssh2_channel_set_blocking; external libssh2_name;
procedure libssh2_channel_handle_extended_data(channel: PLIBSSH2_CHANNEL; ignore: Integer);
var
  I: Integer;
begin
  if ignore <> 0 then
    I := LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE
  else
    I := LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL;
  libssh2_channel_handle_extended_data2(channel, I);
end;
function libssh2_channel_handle_extended_data2; external libssh2_name;
function libssh2_channel_flush_ex; external libssh2_name;
function libssh2_channel_flush(channel: PLIBSSH2_CHANNEL): Integer;
begin
  Result := libssh2_channel_flush_ex(channel, 0);
end;
function libssh2_channel_flush_stderr(channel: PLIBSSH2_CHANNEL): Integer;
begin
  Result := libssh2_channel_flush_ex(channel, SSH_EXTENDED_DATA_STDERR);
end;
function libssh2_channel_get_exit_status; external libssh2_name;
function libssh2_channel_send_eof; external libssh2_name;
function libssh2_channel_eof; external libssh2_name;
function libssh2_channel_wait_eof; external libssh2_name;
function libssh2_channel_close; external libssh2_name;
function libssh2_channel_wait_closed; external libssh2_name;
function libssh2_channel_free; external libssh2_name;
function libssh2_scp_recv; external libssh2_name;
function libssh2_scp_send_ex; external libssh2_name;
function libssh2_scp_send(session: PLIBSSH2_SESSION; const path: PAnsiChar; mode: Integer; size: SIZE_T): PLIBSSH2_CHANNEL;
begin
  Result := libssh2_scp_send_ex(session, path, mode, size, 0, 0);
end;
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

end.
