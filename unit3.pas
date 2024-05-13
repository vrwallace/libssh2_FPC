unit Unit3;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, Spin,
  synautil,   blcksock, libssh2, sockets;

type

  { Tformblackhole }

  Tformblackhole = class(TForm)
    Button1: TButton;
    Button2: TButton;
    editusername: TEdit;
    editpassword: TEdit;
    Editmac: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    SpinEditvlan: TSpinEdit;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure editpasswordChange(Sender: TObject);
    function ConvertMacAddress(const MacAddress: string): string;
  private
    Session: PLIBSSH2_SESSION;
    Socket: Integer;
    Channel: PLIBSSH2_CHANNEL;
    Commands: TStringList;
    Response: string;
    procedure ConnectSSH;
    procedure DisconnectSSH;
    procedure ExecuteCommands;
  public
    { Public declarations }
  end;

var
  formblackhole: Tformblackhole;

implementation

{$R *.lfm}

procedure Tformblackhole.Button1Click(Sender: TObject);
var
  MacAddress, VlanID: string;
begin
  // Assign values to MacAddress and VlanID based on user input
  MacAddress := ConvertMacAddress(Editmac.Text);
  VlanID := IntToStr(SpinEditvlan.Value);

  // Initialize the list of commands
  Commands := TStringList.Create;
  Commands.Add('system-view');
  Commands.Add('undo mac-address blackhole ' + MacAddress + ' vlan ' + VlanID);
  Commands.Add('quit');
  Commands.Add('save');
  Commands.Add('y');
  Commands.Add('');
   Commands.Add('y');
  Commands.Add('');

  try
    // Connect to the SSH server
    ConnectSSH;

    // Execute commands
    ExecuteCommands;

    // Disconnect from the SSH server
    DisconnectSSH;
  except
    on E: Exception do
      ShowMessage('Error: ' + E.Message);
  end;
end;

procedure Tformblackhole.Button2Click(Sender: TObject);
var
  MacAddress, VlanID: string;
begin
  // Assign values to MacAddress and VlanID based on user input
  MacAddress := ConvertMacAddress(Editmac.Text);
  VlanID := IntToStr(SpinEditvlan.Value);

  // Initialize the list of commands
  Commands := TStringList.Create;
  Commands.Add('system-view');
  Commands.Add('mac-address blackhole ' + MacAddress + ' vlan ' + VlanID);
  Commands.Add('quit');
  Commands.Add('save');
   Commands.Add('y');
  Commands.Add('');
   Commands.Add('y');
  Commands.Add('');


  try
    // Connect to the SSH server
    ConnectSSH;

    // Execute commands
    ExecuteCommands;

    // Disconnect from the SSH server
    DisconnectSSH;
  except
    on E: Exception do
      ShowMessage('Error: ' + E.Message);
  end;
end;

procedure Tformblackhole.editpasswordChange(Sender: TObject);
begin

end;



procedure Tformblackhole.ConnectSSH;
var
  SockAddr: TInetSockAddr;
  HostAddr: TInAddr;
  editusernametext, editpasswordtext: AnsiString;
  HostNameStr: AnsiString;
  hostname: AnsiString;
  SocketHandle: TSocket;
begin
  // Assign the values from the edit controls
  editusernametext := AnsiString(editusername.Text);
  editpasswordtext := AnsiString(editpassword.Text);
  hostname := AnsiString('192.168.1.80');

  // Initialize libssh2
  if libssh2_init(0) <> 0 then
    raise Exception.Create('Failed to initialize libssh2');

  // Resolve the hostname
  HostNameStr := AnsiString(hostname);
  HostAddr := StrToNetAddr(HostNameStr);
  if HostAddr.S_addr = longword(INADDR_NONE) then
    raise Exception.Create('Failed to resolve hostname');

  // Create socket and connect to the SSH server
  SocketHandle := fpsocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if SocketHandle = INVALID_SOCKET then
    raise Exception.Create('Failed to create socket');

  SockAddr.sin_family := AF_INET;
  SockAddr.sin_port := htons(22);
  SockAddr.sin_addr := HostAddr;

  if fpconnect(SocketHandle, @SockAddr, SizeOf(SockAddr)) <> 0 then
  begin
    fpshutdown(SocketHandle, SHUT_RDWR);
    CloseSocket(SocketHandle);
    raise Exception.Create('Failed to connect to the SSH server');
  end;

  // Create SSH session
  Session := libssh2_session_init();
  if not Assigned(Session) then
    raise Exception.Create('Failed to create SSH session');

  // Start SSH session
  if libssh2_session_startup(Session, SocketHandle) <> 0 then
    raise Exception.Create('Failed to start SSH session');

  // Authenticate with editusername and editpassword
  if libssh2_userauth_password(Session, PAnsiChar(editusernametext), PAnsiChar(editpasswordtext)) <> 0 then
    raise Exception.Create('Failed to authenticate');
end;




procedure Tformblackhole.DisconnectSSH;
begin
  // Disconnect and free the SSH session
  libssh2_session_disconnect(Session, 'Disconnecting');
  libssh2_session_free(Session);

  // Close the socket
  CloseSocket(Socket);

  // Cleanup libssh2
  libssh2_exit();

end;
procedure TFormBlackHole.ExecuteCommands;
var
  I: Integer;
  Command: AnsiString;
  Buffer: array[0..4095] of AnsiChar;
  BytesRead: Integer;
  TimeoutMs: Integer;
  StartTime: Cardinal;
begin
  // Set the timeout value in milliseconds
  TimeoutMs := 5000; // 5 seconds

  // Open SSH channel
  Channel := libssh2_channel_open_session(Session);
  if Channel = nil then
    raise Exception.Create('Failed to open SSH channel');

  try
    if libssh2_channel_request_pty(Channel, 'vanilla') < 0 then
    begin
      ShowMessage('Failed to PTY');
      Exit;
    end;

    // Request a shell session
    if libssh2_channel_shell(Channel) < 0 then
    begin
      ShowMessage('Failed to request shell session');
      Exit;
    end;
     libssh2_session_set_blocking(session, 0);

    // Execute commands
    for I := 0 to Commands.Count - 1 do
    begin
      Command := AnsiString(Commands[I]);

      // Send the command to the server
      Command := Command + #13#10; // Add CRLF character sequence
       sleep(2500);
      if libssh2_channel_write(Channel, PAnsiChar(Command), Length(Command)) < 0 then
      begin
        ShowMessage('Failed to write command: ' + Command);
        exit; // Skip to the next command if writing fails
      end;

      // Read the response from the server with timeout handling
     { Response := '';
      StartTime := GetTickCount64;
      repeat
        BytesRead := libssh2_channel_read(Channel, @Buffer, SizeOf(Buffer));
        if BytesRead > 0 then
        begin

          //SetString(Response, @Buffer, BytesRead);
         //ShowMessage('Server Response: ' + Response);
         sleep(2500);
        end
        else if BytesRead = LIBSSH2_ERROR_EAGAIN then
        begin
          // Wait for a short period before retrying the read operation
          Sleep(100);
        end
        else if BytesRead < 0 then
        begin
          ShowMessage('Failed to read response for command: ' + Command);
          Break; // Exit loop if read error occurs
        end;
      until (BytesRead <= 0) or (GetTickCount64 - StartTime > TimeoutMs);}

    end;
    showmessage('Blackhole Operation Complete');
  finally
    // Free the SSH channel
   // libssh2_channel_free(Channel);
  end;
end;



function TFormBlackHole.ConvertMacAddress(const MacAddress: string): string;
var
  FormattedMac: string;
  i: integer;
begin
  // Remove hyphens and colons
  FormattedMac := StringReplace(MacAddress, ':', '', [rfReplaceAll]);
  FormattedMac := StringReplace(FormattedMac, '-', '', [rfReplaceAll]);

  // Construct the formatted MAC address
  Result := '';
  for i := 1 to Length(FormattedMac) do
  begin
    Result := Result + FormattedMac[i];
    if (i = 4) or (i = 8) then
      Result := Result + '-';
  end;
end;




end.
