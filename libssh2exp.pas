       unit libssh2;

interface

{$mode delphi}

uses
  ctypes,libssh2;
   {$IFDEF WINDOWS}
  const
    libssh2_name = 'libssh2.dll';
  {$ENDIF}
  {$IFDEF LINUX}
  const
    libssh2_name = 'libssh2.so';
  {$ENDIF}

type
  time_t = Int64;

  LIBSSH2_SESSION = record end;
  PLIBSSH2_SESSION = ^LIBSSH2_SESSION;

  LIBSSH2_CHANNEL = record end;
  PLIBSSH2_CHANNEL = ^LIBSSH2_CHANNEL;

  LIBSSH2_LISTENER = record end;
  PLIBSSH2_LISTENER = ^LIBSSH2_LISTENER;

  LIBSSH2_KNOWNHOSTS = record end;
  PLIBSSH2_KNOWNHOSTS = ^LIBSSH2_KNOWNHOSTS;

  LIBSSH2_AGENT = record end;
  PLIBSSH2_AGENT = ^LIBSSH2_AGENT;

  LIBSSH2_USERAUTH_KBDINT_PROMPT = record
    text: PAnsiChar;
    length: UInt32;
    echo: Byte;
  end;
  PLIBSSH2_USERAUTH_KBDINT_PROMPT = ^LIBSSH2_USERAUTH_KBDINT_PROMPT;

  LIBSSH2_USERAUTH_KBDINT_RESPONSE = record
    text: PAnsiChar;
    length: UInt32;
  end;

  LIBSSH2_KNOWNHOST = record
    magic: UInt32;
    node: Pointer;
    name: PAnsiChar;
    key: PAnsiChar;
    typemask: cint;
  end;
  PLIBSSH2_KNOWNHOST = ^LIBSSH2_KNOWNHOST;

  LIBSSH2_AGENT_PUBLICKEY = record
    magic: UInt32;
    node: Pointer;
    blob: PByte;
    blob_len: size_t;
    comment: PAnsiChar;
  end;
  PLIBSSH2_AGENT_PUBLICKEY = ^LIBSSH2_AGENT_PUBLICKEY;

  LIBSSH2_POLLFD = record
    _type: Byte;
    socket: ctypes.cint;
    channel: PLIBSSH2_CHANNEL;
    listener: PLIBSSH2_LISTENER;
  end;
  PLIBSSH2_POLLFD = ^LIBSSH2_POLLFD;

  Pstruct_stat = ^struct_stat;
  struct_stat = record
    st_dev: UInt64;
    st_ino: UInt32;
    st_mode: UInt32;
    st_nlink: UInt32;
    st_uid: UInt32;
    st_gid: UInt32;
    st_rdev: UInt64;
    st_size: Int64;
    st_atime: time_t;
    st_mtime: time_t;
    st_ctime: time_t;
  end;

  LIBSSH2_SFTP_ATTRIBUTES = record
    flags: UInt32;
    filesize: UInt64;
    uid, gid: UInt32;
    permissions: UInt32;
    atime, mtime: UInt32;
  end;
  PLIBSSH2_SFTP_ATTRIBUTES = ^LIBSSH2_SFTP_ATTRIBUTES;

  LIBSSH2_SFTP_STATVFS = record
    f_bsize: UInt64;
    f_frsize: UInt64;
    f_blocks: UInt64;
    f_bfree: UInt64;
    f_bavail: UInt64;
    f_files: UInt64;
    f_ffree: UInt64;
    f_favail: UInt64;
    f_fsid: UInt64;
    f_flag: UInt64;
    f_namemax: UInt64;
  end;
  PLIBSSH2_SFTP_STATVFS = ^LIBSSH2_SFTP_STATVFS;

  LIBSSH2_ALLOC_FUNC = function(count: size_t; abstract: Pointer): Pointer; cdecl;
  LIBSSH2_REALLOC_FUNC = function(ptr: Pointer; count: size_t; abstract: Pointer): Pointer; cdecl;
  LIBSSH2_FREE_FUNC = procedure(ptr: Pointer; abstract: Pointer); cdecl;

  LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC = function(
    session: PLIBSSH2_SESSION; var sig: PByte; sig_len: size_t;
    const data: PByte; data_len: size_t; abstract: Pointer): cint; cdecl;

  LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC = procedure(
    const name: PAnsiChar; name_len: cint;
    const instruction: PAnsiChar; instruction_len: cint;
    num_prompts: cint; const prompts: PLIBSSH2_USERAUTH_KBDINT_PROMPT;
    var responses: LIBSSH2_USERAUTH_KBDINT_RESPONSE; abstract: Pointer); cdecl;

  LIBSSH2_IGNORE_FUNC = procedure(
    session: PLIBSSH2_SESSION; const message: PAnsiChar;
    message_len: cint; abstract: Pointer); cdecl;

  LIBSSH2_DEBUG_FUNC = procedure(
    session: PLIBSSH2_SESSION; always_display: cint;
    const message: PAnsiChar; message_len: cint;
    const language: PAnsiChar; language_len: cint;
    abstract: Pointer); cdecl;

  LIBSSH2_DISCONNECT_FUNC = procedure(
    session: PLIBSSH2_SESSION; reason: cint;
    const message: PAnsiChar; message_len: cint;
    const language: PAnsiChar; language_len: cint;
    abstract: Pointer); cdecl;

  LIBSSH2_PASSWD_CHANGEREQ_FUNC = procedure(
    session: PLIBSSH2_SESSION; var newpw: PAnsiChar;
    var newpw_len: cint; abstract: Pointer); cdecl;

  LIBSSH2_MACERROR_FUNC = function(
    session: PLIBSSH2_SESSION; const packet: PAnsiChar;
    packet_len: cint; abstract: Pointer): cint; cdecl;

  LIBSSH2_X11_OPEN_FUNC = procedure(
    session: PLIBSSH2_SESSION; channel: PLIBSSH2_CHANNEL;
    const shost: PAnsiChar; sport: cint; abstract: Pointer); cdecl;

  LIBSSH2_CHANNEL_CLOSE_FUNC = procedure(
    session: PLIBSSH2_SESSION; var session_abstract: Pointer;
    channel: PLIBSSH2_CHANNEL; var channel_abstract: Pointer); cdecl;

  LIBSSH2_TRACE_HANDLER_FUNC = procedure(
    session: PLIBSSH2_SESSION; context: Pointer;
    const message: PAnsiChar; message_len: size_t); cdecl;

const
  LIBSSH2_VERSION = '1.2.6';
  LIBSSH2_VERSION_MAJOR = 1;
  LIBSSH2_VERSION_MINOR = 2;
  LIBSSH2_VERSION_PATCH = 6;

  SHA_DIGEST_LENGTH = 20;
  MD5_DIGEST_LENGTH = 16;

  LIBSSH2_VERSION_NUM = $010206;
  LIBSSH2_TIMESTAMP = 'Thu Jun 10 08:19:51 UTC 2010';

  LIBSSH2_SSH_BANNER = 'SSH-2.0-libssh2_' + LIBSSH2_VERSION;
  LIBSSH2_SSH_DEFAULT_BANNER = LIBSSH2_SSH_BANNER;
  LIBSSH2_SSH_DEFAULT_BANNER_WITH_CRLF = LIBSSH2_SSH_DEFAULT_BANNER + #13#10;

  LIBSSH2_DH_GEX_MINGROUP = 1024;
  LIBSSH2_DH_GEX_OPTGROUP = 1536;
  LIBSSH2_DH_GEX_MAXGROUP = 2048;

  LIBSSH2_TERM_WIDTH = 80;
  LIBSSH2_TERM_HEIGHT = 24;
  LIBSSH2_TERM_WIDTH_PX = 0;
  LIBSSH2_TERM_HEIGHT_PX = 0;

  LIBSSH2_SOCKET_POLL_UDELAY = 250000;
  LIBSSH2_SOCKET_POLL_MAXLOOPS = 120;

  LIBSSH2_PACKET_MAXCOMP = 32000;
  LIBSSH2_PACKET_MAXDECOMP = 40000;
  LIBSSH2_PACKET_MAXPAYLOAD = 40000;

  LIBSSH2_CHANNEL_WINDOW_DEFAULT = 65536;
  LIBSSH2_CHANNEL_PACKET_DEFAULT = 32768;
  LIBSSH2_CHANNEL_MINADJUST = 1024;

  LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL = 0;
  LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE = 1;
  LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE = 2;

  SSH_EXTENDED_DATA_STDERR = 1;

  LIBSSH2_SFTP_OPENFILE = 0;
  LIBSSH2_SFTP_OPENDIR = 1;

  LIBSSH2_FXF_READ = $00000001;
  LIBSSH2_FXF_WRITE = $00000002;
  LIBSSH2_FXF_APPEND = $00000004;
  LIBSSH2_FXF_CREAT = $00000008;
  LIBSSH2_FXF_TRUNC = $00000010;
  LIBSSH2_FXF_EXCL = $00000020;

  LIBSSH2_SFTP_ATTR_SIZE = $00000001;
  LIBSSH2_SFTP_ATTR_UIDGID = $00000002;
  LIBSSH2_SFTP_ATTR_PERMISSIONS = $00000004;
  LIBSSH2_SFTP_ATTR_ACMODTIME = $00000008;
  LIBSSH2_SFTP_ATTR_EXTENDED = $80000000;

  LIBSSH2_SFTP_REALPATH = 0;
  LIBSSH2_SFTP_STAT = 1;

  LIBSSH2_SFTP_SYMLINK_READLINK = 0;
  LIBSSH2_SFTP_SYMLINK_REALPATH = 1;

  LIBSSH2_SFTP_RENAME_OVERWRITE = $00000001;
  LIBSSH2_SFTP_RENAME_ATOMIC = $00000002;
  LIBSSH2_SFTP_RENAME_NATIVE = $00000004;

  LIBSSH2_CALLBACK_IGNORE = 0;
  LIBSSH2_CALLBACK_DEBUG = 1;
  LIBSSH2_CALLBACK_DISCONNECT = 2;
  LIBSSH2_CALLBACK_MACERROR = 3;
  LIBSSH2_CALLBACK_X11 = 4;

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

  LIBSSH2_FLAG_SIGPIPE = $00000001;

  LIBSSH2_POLLFD_SOCKET = 1;
  LIBSSH2_POLLFD_CHANNEL = 2;
  LIBSSH2_POLLFD_LISTENER = 3;

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

  LIBSSH2_SESSION_BLOCK_INBOUND = $0001;
  LIBSSH2_SESSION_BLOCK_OUTBOUND = $0002;

  LIBSSH2_HOSTKEY_HASH_MD5 = 1;
  LIBSSH2_HOSTKEY_HASH_SHA1 = 2;

  LIBSSH2_HOSTKEY_TYPE_UNKNOWN = 0;
  LIBSSH2_HOSTKEY_TYPE_RSA = 1;
  LIBSSH2_HOSTKEY_TYPE_DSS = 2;

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
LIBSSH2_INIT_NO_CRYPTO = $0001;
SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
SSH_OPEN_CONNECT_FAILED = 2;
SSH_OPEN_UNKNOWN_CHANNELTYPE = 3;
SSH_OPEN_RESOURCE_SHORTAGE = 4;
LIBSSH2_TRACE_TRANS = (1 shl 1);
LIBSSH2_TRACE_KEX = (1 shl 2);
LIBSSH2_TRACE_AUTH = (1 shl 3);
LIBSSH2_TRACE_CONN = (1 shl 4);
LIBSSH2_TRACE_SCP = (1 shl 5);
LIBSSH2_TRACE_SFTP = (1 shl 6);
LIBSSH2_TRACE_ERROR = (1 shl 7);
LIBSSH2_TRACE_PUBLICKEY = (1 shl 8);
LIBSSH2_TRACE_SOCKET = (1 shl 9);
function libssh2_init(flags: cint): cint; cdecl;
procedure libssh2_exit(); cdecl;
function libssh2_session_init_ex(my_alloc: LIBSSH2_ALLOC_FUNC;
my_free: LIBSSH2_FREE_FUNC; my_realloc: LIBSSH2_REALLOC_FUNC;
abstract: Pointer): PLIBSSH2_SESSION; cdecl;
function libssh2_session_abstract(session: PLIBSSH2_SESSION): Pointer; cdecl;
function libssh2_session_callback_set(session: PLIBSSH2_SESSION;
cbtype: cint; callback: Pointer): Pointer; cdecl;
function libssh2_banner_set(session: PLIBSSH2_SESSION;
const banner: PAnsiChar): cint; cdecl;
function libssh2_session_startup(session: PLIBSSH2_SESSION;
socket: cint): cint; cdecl;
function libssh2_session_disconnect_ex(session: PLIBSSH2_SESSION;
reason: cint; const description: PAnsiChar;
const lang: PAnsiChar): cint; cdecl;
function libssh2_session_free(session: PLIBSSH2_SESSION): cint; cdecl;
function libssh2_hostkey_hash(session: PLIBSSH2_SESSION;
hash_type: cint): PAnsiChar; cdecl;
function libssh2_session_hostkey(session: PLIBSSH2_SESSION;
var len: size_t; var _type: cint): PAnsiChar; cdecl;
function libssh2_session_method_pref(session: PLIBSSH2_SESSION;
method_type: cint; const prefs: PAnsiChar): cint; cdecl;
function libssh2_session_methods(session: PLIBSSH2_SESSION;
method_type: cint): PAnsiChar; cdecl;
function libssh2_session_last_error(session: PLIBSSH2_SESSION;
var errmsg: PAnsiChar; var errmsg_len: cint; want_buf: cint): cint; cdecl;
function libssh2_session_last_errno(session: PLIBSSH2_SESSION): cint; cdecl;
function libssh2_session_block_directions(session: PLIBSSH2_SESSION): cint; cdecl;
function libssh2_session_flag(session: PLIBSSH2_SESSION;
flag: cint; value: cint): cint; cdecl;
function libssh2_userauth_list(session: PLIBSSH2_SESSION;
const username: PAnsiChar; username_len: UInt32): PAnsiChar; cdecl;
function libssh2_userauth_authenticated(session: PLIBSSH2_SESSION): cint; cdecl;
function libssh2_userauth_password_ex(session: PLIBSSH2_SESSION;
const username: PAnsiChar; username_len: UInt32;
const password: PAnsiChar; password_len: UInt32;
passwd_change_cb: LIBSSH2_PASSWD_CHANGEREQ_FUNC): cint; cdecl;
function libssh2_userauth_publickey_fromfile_ex(session: PLIBSSH2_SESSION;
const username: PAnsiChar; username_len: UInt32;
const publickey: PAnsiChar; const privatekey: PAnsiChar;
const passphrase: PAnsiChar): cint; cdecl;
function libssh2_userauth_hostbased_fromfile_ex(session: PLIBSSH2_SESSION;
const username: PAnsiChar; username_len: UInt32;
const publickey: PAnsiChar; const privatekey: PAnsiChar;
const passphrase: PAnsiChar; const hostname: PAnsiChar;
hostname_len: UInt32; local_username: PAnsiChar;
local_username_len: UInt32): cint; cdecl;
function libssh2_userauth_keyboard_interactive_ex(session: PLIBSSH2_SESSION;
const username: PAnsiChar; username_len: UInt32;
response_callback: LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC): cint; cdecl;
function libssh2_poll(var fds: LIBSSH2_POLLFD;
nfds: UInt32; timeout: clong): cint; cdecl;
function libssh2_channel_open_ex(session: PLIBSSH2_SESSION;
const channel_type: PAnsiChar; channel_type_len: UInt32;
window_size: UInt32; packet_size: UInt32;
const message: PAnsiChar; message_len: UInt32): PLIBSSH2_CHANNEL; cdecl;
function libssh2_channel_direct_tcpip_ex(session: PLIBSSH2_SESSION;
const host: PAnsiChar; port: cint;
const shost: PAnsiChar; sport: cint): PLIBSSH2_CHANNEL; cdecl;
function libssh2_channel_forward_listen_ex(session: PLIBSSH2_SESSION;
const host: PAnsiChar; port: cint;
var bound_port: cint; queue_maxsize: cint): PLIBSSH2_LISTENER; cdecl;
function libssh2_channel_forward_cancel(listener: PLIBSSH2_LISTENER): cint; cdecl;
function libssh2_channel_forward_accept(listener: PLIBSSH2_LISTENER): PLIBSSH2_CHANNEL; cdecl;
function libssh2_channel_setenv_ex(channel: PLIBSSH2_CHANNEL;
const varname: PAnsiChar; varname_len: UInt32;
const value: PAnsiChar; value_len: UInt32): cint; cdecl;
function libssh2_channel_request_pty_ex(channel: PLIBSSH2_CHANNEL;
const term: PAnsiChar; term_len: UInt32;
const modes: PAnsiChar; modes_len: UInt32;
width: cint; height: cint; width_px: cint; height_px: cint): cint; cdecl;
function libssh2_channel_request_pty_size_ex(channel: PLIBSSH2_CHANNEL;
width: cint; height: cint; width_px: cint; height_px: cint): cint; cdecl;
function libssh2_channel_x11_req_ex(channel: PLIBSSH2_CHANNEL;
single_connection: cint; const auth_proto: PAnsiChar;
const auth_cookie: PAnsiChar; screen_number: cint): cint; cdecl;
function libssh2_channel_process_startup(channel: PLIBSSH2_CHANNEL;
const request: PAnsiChar; request_len: UInt32;
const message: PAnsiChar; message_len: UInt32): cint; cdecl;
function libssh2_channel_read_ex(channel: PLIBSSH2_CHANNEL;
stream_id: cint; buf: PAnsiChar; buflen: size_t): cint; cdecl;
function libssh2_poll_channel_read(channel: PLIBSSH2_CHANNEL;
extended: cint): cint; cdecl;
function libssh2_channel_window_read_ex(channel: PLIBSSH2_CHANNEL;
var read_avail: clong; var window_size_initial: clong): UInt32; cdecl;
function libssh2_channel_receive_window_adjust(channel: PLIBSSH2_CHANNEL;
adjustment: clong; force: Byte): clong; cdecl;
function libssh2_channel_receive_window_adjust2(channel: PLIBSSH2_CHANNEL;
adjustment: clong; force: Byte; var storewindow: UInt32): cint; cdecl;
function libssh2_channel_write_ex(channel: PLIBSSH2_CHANNEL;
stream_id: cint; const buf: PAnsiChar; buflen: size_t): cint; cdecl;
function libssh2_channel_window_write_ex(channel: PLIBSSH2_CHANNEL;
var window_size_initial: clong): UInt32; cdecl;
procedure libssh2_session_set_blocking(session: PLIBSSH2_SESSION;
blocking: cint); cdecl;
function libssh2_session_get_blocking(session: PLIBSSH2_SESSION): cint; cdecl;
procedure libssh2_channel_set_blocking(channel: PLIBSSH2_CHANNEL;
blocking: cint); cdecl;
procedure libssh2_channel_handle_extended_data(channel: PLIBSSH2_CHANNEL;
ignore_mode: cint); cdecl;
function libssh2_channel_handle_extended_data2(channel: PLIBSSH2_CHANNEL;
ignore_mode: cint): cint; cdecl;
function libssh2_channel_flush_ex(channel: PLIBSSH2_CHANNEL;
streamid: cint): cint; cdecl;
function libssh2_channel_get_exit_status(channel: PLIBSSH2_CHANNEL): cint; cdecl;
function libssh2_channel_send_eof(channel: PLIBSSH2_CHANNEL): cint; cdecl;
function libssh2_channel_eof(channel: PLIBSSH2_CHANNEL): cint; cdecl;
function libssh2_channel_wait_eof(channel: PLIBSSH2_CHANNEL): cint; cdecl;
function libssh2_channel_close(channel: PLIBSSH2_CHANNEL): cint; cdecl;
function libssh2_channel_wait_closed(channel: PLIBSSH2_CHANNEL): cint; cdecl;
function libssh2_channel_free(channel: PLIBSSH2_CHANNEL): cint; cdecl;
function libssh2_scp_recv(session: PLIBSSH2_SESSION;
const path: PAnsiChar; var sb: struct_stat): PLIBSSH2_CHANNEL; cdecl;
function libssh2_scp_send_ex(session: PLIBSSH2_SESSION;
const path: PAnsiChar; mode: cint; size: size_t;
mtime: clong; atime: clong): PLIBSSH2_CHANNEL; cdecl;
function libssh2_scp_send64(session: PLIBSSH2_SESSION;
const path: PAnsiChar; mode: cint; size: UInt64;
mtime: time_t; atime: time_t): PLIBSSH2_CHANNEL; cdecl;
function libssh2_base64_decode(session: PLIBSSH2_SESSION;
var dest: PAnsiChar; var dest_len: UInt32;
const src: PAnsiChar; src_len: UInt32): cint; cdecl;
function libssh2_knownhost_init(session: PLIBSSH2_SESSION): PLIBSSH2_KNOWNHOSTS; cdecl;
function libssh2_knownhost_add(hosts: PLIBSSH2_KNOWNHOSTS;
host, salt, key: PAnsiChar; keylen: size_t; typemask: cint;
var store: PLIBSSH2_KNOWNHOST): cint; cdecl;
function libssh2_knownhost_addc(hosts: PLIBSSH2_KNOWNHOSTS;
host, salt, key: PAnsiChar; keylen: size_t; comment: PAnsiChar;
commentlen: size_t; typemask: cint; var store: PLIBSSH2_KNOWNHOST): cint; cdecl;
function libssh2_knownhost_check(hosts: PLIBSSH2_KNOWNHOSTS;
host, key: PAnsiChar; keylen: size_t; typemask: cint;
var knownhost: PLIBSSH2_KNOWNHOST): cint; cdecl;
function libssh2_knownhost_checkp(hosts: PLIBSSH2_KNOWNHOSTS;
const host: PAnsiChar; port: cint;
const key: PAnsiChar; keylen: size_t; typemask: cint;
var knownhost: PLIBSSH2_KNOWNHOST): cint; cdecl;
function libssh2_knownhost_del(hosts: PLIBSSH2_KNOWNHOSTS;
entry: PLIBSSH2_KNOWNHOST): cint; cdecl;
procedure libssh2_knownhost_free(hosts: PLIBSSH2_KNOWNHOSTS); cdecl;
function libssh2_knownhost_readline(hosts: PLIBSSH2_KNOWNHOSTS;
const line: PAnsiChar; len: size_t; _type: cint): cint; cdecl;
function libssh2_knownhost_readfile(hosts: PLIBSSH2_KNOWNHOSTS;
const filename: PAnsiChar; _type: cint): cint; cdecl;
function libssh2_knownhost_writeline(hosts: PLIBSSH2_KNOWNHOSTS;
known: PLIBSSH2_KNOWNHOST; buffer: PAnsiChar; buflen: size_t;
var outlen: size_t; _type: cint): cint; cdecl;
function libssh2_knownhost_writefile(hosts: PLIBSSH2_KNOWNHOSTS;
const filename: PAnsiChar; _type: cint): cint; cdecl;
function libssh2_knownhost_get(hosts: PLIBSSH2_KNOWNHOSTS;
var store: PLIBSSH2_KNOWNHOST; prev: PLIBSSH2_KNOWNHOST): cint; cdecl;
function libssh2_agent_init(session: PLIBSSH2_SESSION): PLIBSSH2_AGENT; cdecl;
function libssh2_agent_connect(agent: PLIBSSH2_AGENT): cint; cdecl;
function libssh2_agent_list_identities(agent: PLIBSSH2_AGENT): cint; cdecl;
function libssh2_agent_get_identity(agent: PLIBSSH2_AGENT;
var store: PLIBSSH2_AGENT_PUBLICKEY; prev: PLIBSSH2_AGENT_PUBLICKEY): cint; cdecl;
function libssh2_agent_userauth(agent: PLIBSSH2_AGENT;
const username: PAnsiChar; identity: PLIBSSH2_AGENT_PUBLICKEY): cint; cdecl;
function libssh2_agent_disconnect(agent: PLIBSSH2_AGENT): cint; cdecl;
procedure libssh2_agent_free(agent: PLIBSSH2_AGENT); cdecl;
procedure libssh2_keepalive_config(session: PLIBSSH2_SESSION;
want_reply: cint; interval: UInt32); cdecl;
function libssh2_keepalive_send(session: PLIBSSH2_SESSION;
var seconds_to_next: cint): cint; cdecl;
function libssh2_trace(session: PLIBSSH2_SESSION; bitmask: cint): cint; cdecl;
function libssh2_trace_sethandler(session: PLIBSSH2_SESSION;
context: Pointer; callback: LIBSSH2_TRACE_HANDLER_FUNC): cint; cdecl;
implementation
{$linklib ssh2}
end.
