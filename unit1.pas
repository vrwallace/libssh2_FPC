unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, FileUtil, TAGraph, TASeries, Forms,
  Controls, Graphics, Dialogs, StdCtrls, ExtCtrls, Menus, snmpsend, tatypes,
  synautil, StrUtils, TACustomSeries, unit2, unit3,sqlite3conn, sqldb, blcksock, sockets,resolve;


type
  { TifOutErrors }

  TifOutErrors = class(TForm)
    Button1: TButton;
    Button2: TButton;
    Button3: TButton;
    Button4: TButton;
    Button5: TButton;
    Button6: TButton;
    chart1: TChart;
    chart1LineSeries1: TLineSeries;
    chart1LineSeries2: TLineSeries;
    chart1LineSeries3: TLineSeries;
    chart1LineSeries4: TLineSeries;
    dropdown: TComboBox;
    EditIFInOctets: TEdit;
    EditIFOutOctets: TEdit;
    EditIFInErrors: TEdit;
    EditIFOutErrors: TEdit;
    ifouterrors: TEdit;
    ifInErrors: TEdit;
    ifOutOctets: TEdit;
    ifInOctets: TEdit;
    Label1: TLabel;
    Label10: TLabel;
    Label11: TLabel;
    Label12: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    Label5: TLabel;
    Label6: TLabel;
    Label7: TLabel;
    Label8: TLabel;
    Label9: TLabel;
    snmp: TEdit;
    Timer1: TTimer;
    host: TEdit;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure Button3Click(Sender: TObject);
    procedure Button4Click(Sender: TObject);
    procedure Button5Click(Sender: TObject);
    procedure Button6Click(Sender: TObject);
    procedure dropdownChange(Sender: TObject);



    procedure Timer1Timer(Sender: TObject);
    function FormatMacAddress(macAddress: string): string;
    function FormatIPAddress(ipAddress: string): string;
    function HexToDec(const Hex: string): integer;
    function MACAddressToDecimal(const MACAddress: string): string;
    function StrToHexStr(const s: string): string;
    procedure CalculatePacketRateForAllSeries(Chart2: TChart);
    function LookupMAC(macPrefix: string; out ShortName, LongName: string;
      dbname: string): boolean;
  var



  private
    { private declarations }

    procedure AddToSeries(LineSeries: TLineSeries; Value: double;
      MaxDataPoints: integer);
  public
    { public declarations }
    // property SelectedText: string read FSelectedText write FSelectedText;
  end;

var
  ifOutErrors: TifOutErrors;

implementation

{$R *.lfm}

{ TifOutErrors }

procedure TifOutErrors.AddToSeries(LineSeries: TLineSeries; Value: double;
  MaxDataPoints: integer);
var
  XValue: double;
  i: integer;
begin

  if LineSeries.Count > 0 then
  begin
    XValue := LineSeries.XValue[LineSeries.Count - 1] + 1;
  end
  else
  begin
    XValue := 0;
  end;

  LineSeries.AddXY(XValue, Value);

  if LineSeries.Count > MaxDataPoints then
  begin
    LineSeries.Delete(0);
    LineSeries.XValue[0] := 0;
    for i := 1 to LineSeries.Count - 1 do
      LineSeries.XValue[i] := LineSeries.XValue[i - 1] + 1;
  end;

  if LineSeries.Count > 0 then
  begin
    Chart1.BottomAxis.Range.Min := LineSeries.XValue[0];
    Chart1.BottomAxis.Range.Max := LineSeries.XValue[LineSeries.Count - 1];
    Chart1.BottomAxis.Intervals.MinLength := 1;
    Chart1.BottomAxis.Intervals.Tolerance := 1;
  end;
end;

procedure TifOutErrors.Timer1Timer(Sender: TObject);
var
  SNMPResult: boolean;
  snmpval, ipaddrval: string;
  rtval: ansistring;
  floatValue: double;
  MaxDataPoints: integer;
  selectedInterfaceIndex: integer;
  SelectedText: string;
  OpenParenPos, CloseParenPos: integer;
  NumberStr: string;
begin

  snmpval := trim(snmp.Text);
  ipaddrval := trim(host.Text);
  MaxDataPoints := 1000;
  rtval := '';
  floatValue := 0;
  selectedInterfaceIndex := 0;

  if trim(DropDown.Text) <> '' then
  begin
    SelectedText := dropdown.Text;
    OpenParenPos := Pos('(', SelectedText);
    CloseParenPos := Pos(')', SelectedText);

    if (OpenParenPos > 0) and (CloseParenPos > OpenParenPos) then
    begin
      NumberStr := Copy(SelectedText, OpenParenPos + 1, CloseParenPos -
        OpenParenPos - 1);
      SelectedInterfaceIndex := StrToInt(NumberStr);
    end;

    // Interface MIB - Total octets received on the interface
    SNMPResult := SNMPGet('1.3.6.1.2.1.2.2.1.10.' + IntToStr(selectedInterfaceIndex),
      snmpval, ipaddrval, rtval);
    if SNMPResult then
    begin
      ifInOctets.Text := FormatFloat('#,##0', strtofloat(rtval));
      if TryStrToFloat(rtval, floatValue) then
        AddToSeries(Chart1.Series[0] as TLineSeries, floatValue, MaxDataPoints);
    end;

    // Interface MIB - Total octets transmitted out of the interface
    SNMPResult := SNMPGet('1.3.6.1.2.1.2.2.1.16.' + IntToStr(selectedInterfaceIndex),
      snmpval, ipaddrval, rtval);
    if SNMPResult then
    begin
      ifOutOctets.Text := FormatFloat('#,##0', strtofloat(rtval));
      if TryStrToFloat(rtval, floatValue) then
        AddToSeries(Chart1.Series[1] as TLineSeries, floatValue, MaxDataPoints);
    end;

    // Interface MIB - Number of inbound packets that contained errors
    SNMPresult := SNMPGet('1.3.6.1.2.1.2.2.1.14.' + IntToStr(selectedInterfaceIndex),
      snmpval, ipaddrval, rtval);
    if SNMPresult then
    begin
      ifInErrors.Text := FormatFloat('#,##0', strtofloat(rtval));
      if TryStrToFloat(rtval, floatValue) then
        AddToSeries(Chart1.Series[2] as TLineSeries, floatValue, MaxDataPoints);
    end;

    // Interface MIB - Number of outbound packets that contained errors
    SNMPResult := SNMPGet('1.3.6.1.2.1.2.2.1.20.' + IntToStr(selectedInterfaceIndex),
      snmpval, ipaddrval, rtval);
    if SNMPResult then
    begin
      ifOutErrors.Text := FormatFloat('#,##0', strtofloat(rtval));
      if TryStrToFloat(rtval, floatValue) then
        AddToSeries(Chart1.Series[3] as TLineSeries, floatValue, MaxDataPoints);
    end;

    Chart1.Invalidate; // Refresh the chart
    CalculatePacketRateForAllSeries(Chart1);
    timer1.Enabled := True;
    button1.Enabled := False;
  end
  else
    ShowMessage('Select Interface!');

end;

procedure TifOutErrors.Button1Click(Sender: TObject);
var
  SNMPResult: boolean;
  i: integer;
  snmpval, ipaddrval, rtval: string;
begin
  snmpval := Trim(snmp.Text);
  ipaddrval := Trim(host.Text);

  if ((trim(snmpval) <> '') and (trim(ipaddrval) <> '')) then
  begin

    for i := 0 to Chart1.SeriesCount - 1 do
    begin
      if (Chart1.Series[i] is TChartSeries) then
        TChartSeries(Chart1.Series[i]).Clear;
    end;
    Chart1.Invalidate;
    SNMPResult := SNMPGet('1.3.6.1.2.1.1.1.0', SNMPval, ipaddrval, rtval);
    if not SNMPResult then
    begin
      ShowMessage('Failed test SNMPGet, check Community Name or Host!');
      timer1.Enabled := False;
      button1.Enabled := True;
      Exit;
    end
    else
    begin
      if trim(DropDown.Text) <> '' then
        Timer1Timer(nil)
      else
      begin
        ShowMessage('Select Interface!');
        timer1.Enabled := False;
        button1.Enabled := True;
      end;
    end;
  end
  else
  begin
    ShowMessage('Need Server and community name!');
    timer1.Enabled := False;
    button1.Enabled := True;
  end;
end;

procedure TifOutErrors.Button2Click(Sender: TObject);
var
  SNMPResult: boolean;
  snmpval, ipaddrval: string;
  currentOID: string;
  retrievedValue: string;
  interfaceIndex: integer;
  interfaceName, baseoid: string;
  parts: TStringArray;
  rtval: ansistring;
begin
  timer1.Enabled := False;
  button1.Enabled := True;

  snmpval := Trim(snmp.Text);
  ipaddrval := Trim(host.Text);

  DropDown.Items.Clear;

  if ((trim(snmpval) <> '') and (trim(ipaddrval) <> '')) then
  begin
    SNMPResult := SNMPGet('1.3.6.1.2.1.1.1.0', SNMPval, ipaddrval, rtval);
    if not SNMPResult then
    begin
      ShowMessage('Failed test SNMPGet, check Community Name or Host!');
      timer1.Enabled := False;
      button1.Enabled := True;
      Exit;
    end;
  end
  else
  begin
    ShowMessage('Need Server and community name!');
    timer1.Enabled := False;
    button1.Enabled := True;
    exit;
  end;

  baseoid := '1.3.6.1.2.1.2.2.1.2';
  currentOID := baseoid;

  repeat
    SNMPResult := SNMPGetNext(currentOID, snmpval, ipaddrval, retrievedValue);
    if SNMPResult then

    begin
      if pos(baseoid, currentoid) > 0 then
      begin
        parts := SplitString(currentOID, '.');
        interfaceIndex := StrToInt(parts[High(parts)]);
        // interfaceIndex := StrToInt(parts[Length(parts) - 1]);
        interfaceName := retrievedValue;
        DropDown.Items.Add(interfaceName + ' (' + IntToStr(interfaceIndex) + ')');
      end
      else
      begin
        SNMPResult := False;
      end;
    end;
  until not SNMPResult;

  if DropDown.Items.Count = 0 then
  begin
    ShowMessage('No interfaces found');
    timer1.Enabled := False;
    button1.Enabled := True;
  end
  else
    dropdown.ItemIndex := 0;
end;

procedure TifOutErrors.Button3Click(Sender: TObject);
begin
  timer1.Enabled := False;
  button1.Enabled := True;
end;

procedure TifOutErrors.Button4Click(Sender: TObject);
var
  i: integer;
begin
  for i := 0 to Chart1.SeriesCount - 1 do
  begin
    if (Chart1.Series[i] is TChartSeries) then
      TChartSeries(Chart1.Series[i]).Clear;
  end;
  Chart1.Invalidate;
end;

{procedure TifOutErrors.Button5Click(Sender: TObject);
var
  SNMPResult: boolean;
  snmpval, ipaddrval: string;
  currentOID, baseoid: string;
  retrievedValue, mactemp: string;
  oid: string;
  interfaceIndex: integer;
  macAddress, ipAddress, s, ip: string;
  parts: array of string;
  j, i, macindex: integer;
  List: TStringList;
  connectedDevices, macIpList: TStringList;
begin
  snmpval := Trim(snmp.Text);
  ipaddrval := Trim(host.Text);

  if trim(DropDown.Text) <> '' then
  begin
    Button5.Caption := 'Please Wait...';
    try
      parts := SplitString(DropDown.Text, '(');
      interfaceIndex := StrToInt(Copy(parts[1], 1, Pos(')', parts[1]) - 1));


      Form2.MemoConnectedDevices.Clear;
      connectedDevices := TStringList.Create;

      // Retrieve MAC addresses of connected devices for the specific interface index
      currentOID := '1.3.6.1.2.1.17.4.3.1.2.' + IntToStr(interfaceIndex);

      repeat
        // Retrieve the next OID in the dot1dTpFdbTable for the specific interface index
        SNMPResult := SNMPGetNext(currentOID, snmpval, ipaddrval, retrievedValue);

        if SNMPResult then
        begin
          // Extract the MAC address from the OID
          // macAddress := Copy(currentOID, Length('1.3.6.1.2.1.17.4.3.1.2.' + IntToStr(interfaceIndex) + '.') + 1, MaxInt);
          if not CurrentOID.StartsWith('1.3.6.1.2.1.17.4.3.1.2') then
            Break;

          parts := SplitString(currentOID, '.');
          macAddress := '';

          for i := Length(parts) - 6 to Length(parts) do
          begin
            if i = Length(parts) - 6 then
              macAddress := parts[i]
            else
              macAddress := macAddress + '.' + parts[i];
          end;



          mactemp := macAddress;
          List := TStringList.Create;
          try
            List.Delimiter := '.';
            List.DelimitedText := mactemp;
            macaddress := '';

            for macindex := 0 to 5 do
            begin
              if macindex = 0 then
                macaddress := IntToHex(StrToInt(List[macindex]), 2)
              else
                macaddress := macaddress + '-' + IntToHex(StrToInt(List[macindex]), 2);
            end;
          finally
            List.Free;
          end;

          // Add the MAC address to the list
          connectedDevices.Add(macaddress);
        end;
      until not SNMPResult;



      macIpList := TStringList.Create;
      baseOID := '1.3.6.1.2.1.4.22.1.2';
      oid := baseOID;

      repeat
        SNMPResult := SNMPGetNext(oid, snmpval, ipaddrval, s);
        if SNMPResult then
        begin
          if Pos(BaseOID, OID) <> 1 then
            Break;

          macAddress := '';
          for macIndex := 1 to 6 do
          begin
            if macIndex = 1 then
              macAddress := StrToHexStr(s[macIndex])
            else
              macAddress := macAddress + '-' + StrToHexStr(s[macIndex]);
          end;

          List := TStringList.Create;
          try
            List.Delimiter := '.';
            List.DelimitedText := oid;
            ip := List[11] + '.' + List[12] + '.' + List[13] + '.' + List[14];
          finally
            List.Free;
          end;

          // Check if the MAC address is in the connectedDevices list
          if connectedDevices.IndexOf(macAddress) >= 0 then
            macIpList.Add(macAddress + '=' + ip);
        end;
      until not SNMPResult;

      // Update the connectedDevices list with the retrieved IP addresses
      for i := 0 to connectedDevices.Count - 1 do
      begin
        macAddress := connectedDevices[i];
        ipAddress := '';
        for j := 0 to macIpList.Count - 1 do
        begin
          parts := SplitString(macIpList[j], '=');
          if parts[0] = macAddress then
          begin
            ipAddress := parts[1];
            Break;
          end;
        end;
        connectedDevices[i] := macAddress + '=' + ipAddress;
      end;



    finally
      button5.Caption := 'Show Connected Devices';
    end;
    Form2.MemoConnectedDevices.Lines.Add('MAC Address' + #9 + 'IP Address');
    // Display the connected devices with their MAC addresses and IP addresses
    for i := 0 to connectedDevices.Count - 1 do
    begin
      parts := SplitString(connectedDevices[i], '=');
      Form2.MemoConnectedDevices.Lines.Add(parts[0] + #9 + parts[1]);
    end;

    connectedDevices.Free;
    Form2.ShowModal;
  end
  else
  begin
    ShowMessage('Select an interface!');
  end;
end;}


procedure TifOutErrors.Button5Click(Sender: TObject);
var
  SNMPResult: boolean;
  snmpval, ipaddrval: string;
  currentOID, baseoid: string;
  retrievedValue, mactemp: string;
  oid: string;
  interfaceIndex: integer;
  macAddress, ipAddress, s, ip: string;
  parts: array of string;
  j, i, macindex: integer;
  List: TStringList;
  connectedDevices, macIpList: TStringList;
  ShortName, LongName: string;
  MACPrefix, dbname: string;
  dbPath: string;
begin
  snmpval := Trim(snmp.Text);
  ipaddrval := Trim(host.Text);

  if trim(DropDown.Text) <> '' then
  begin
    Button5.Caption := 'Please Wait...';
    try
      parts := SplitString(DropDown.Text, '(');
      interfaceIndex := StrToInt(Copy(parts[1], 1, Pos(')', parts[1]) - 1));

      Form2.StringGridConnectedDevices.Clear;
      Form2.StringGridConnectedDevices.RowCount := 1;
      Form2.StringGridConnectedDevices.Cells[0, 0] := 'MAC Address';
      Form2.StringGridConnectedDevices.Cells[1, 0] := 'IP Address';
      Form2.StringGridConnectedDevices.Cells[2, 0] := 'Manufacturer';
      connectedDevices := TStringList.Create;

      // Retrieve MAC addresses of connected devices for the specific interface index
      currentOID := '1.3.6.1.2.1.17.4.3.1.2.' + IntToStr(interfaceIndex);

      repeat
        // Retrieve the next OID in the dot1dTpFdbTable for the specific interface index
        SNMPResult := SNMPGetNext(currentOID, snmpval, ipaddrval, retrievedValue);

        if SNMPResult then
        begin
          // Extract the MAC address from the OID
          if not CurrentOID.StartsWith('1.3.6.1.2.1.17.4.3.1.2') then
            Break;

          parts := SplitString(currentOID, '.');
          macAddress := '';

          for i := Length(parts) - 6 to Length(parts) do
          begin
            if i = Length(parts) - 6 then
              macAddress := parts[i]
            else
              macAddress := macAddress + '.' + parts[i];
          end;

          mactemp := macAddress;
          List := TStringList.Create;
          try
            List.Delimiter := '.';
            List.DelimitedText := mactemp;
            macaddress := '';

            for macindex := 0 to 5 do
            begin
              if macindex = 0 then
                macaddress := IntToHex(StrToInt(List[macindex]), 2)
              else
                macaddress := macaddress + '-' + IntToHex(StrToInt(List[macindex]), 2);
            end;
          finally
            List.Free;
          end;

          // Add the MAC address to the list
          connectedDevices.Add(macaddress);
        end;
      until not SNMPResult;

      macIpList := TStringList.Create;
      baseOID := '1.3.6.1.2.1.4.22.1.2';
      oid := baseOID;

      repeat
        SNMPResult := SNMPGetNext(oid, snmpval, ipaddrval, s);
        if SNMPResult then
        begin
          if Pos(BaseOID, OID) <> 1 then
            Break;

          macAddress := '';
          for macIndex := 1 to 6 do
          begin
            if macIndex = 1 then
              macAddress := IntToHex(Ord(s[macIndex]), 2)
            else
              macAddress := macAddress + '-' + IntToHex(Ord(s[macIndex]), 2);
          end;

          List := TStringList.Create;
          try
            List.Delimiter := '.';
            List.DelimitedText := oid;
            ip := List[11] + '.' + List[12] + '.' + List[13] + '.' + List[14];
          finally
            List.Free;
          end;

          // Check if the MAC address is in the connectedDevices list
          if connectedDevices.IndexOf(macAddress) >= 0 then
            macIpList.Add(macAddress + '=' + ip);
        end;
      until not SNMPResult;

      // Update the connectedDevices list with the retrieved IP addresses
      for i := 0 to connectedDevices.Count - 1 do
      begin
        macAddress := connectedDevices[i];
        ipAddress := '';
        for j := 0 to macIpList.Count - 1 do
        begin
          parts := SplitString(macIpList[j], '=');
          if parts[0] = macAddress then
          begin
            ipAddress := parts[1];
            Break;
          end;
        end;
        connectedDevices[i] := macAddress + '=' + ipAddress;
      end;

      // Set the path for mac.db
      dbPath := ExtractFilePath(ParamStr(0)) + 'mac.db';

      // Display the connected devices with their MAC addresses, IP addresses, and manufacturers
      for i := 0 to connectedDevices.Count - 1 do
      begin
        parts := SplitString(connectedDevices[i], '=');
        MACAddress := parts[0];

        // Replace hyphens with colons and extract the MAC prefix (first 8 characters)
        if Pos('-', MACAddress) = 3 then
        begin
          MACPrefix := StringReplace(Copy(MACAddress, 1, 20), '-', ':', [rfReplaceAll]);
          dbname := dbPath;

          if FileExists(dbname) then
          begin
            // Call the function to look up the MAC manufacturer using the prefix
            LookupMAC(MACPrefix, ShortName, LongName, dbname);
          end
          else
          begin
            ShortName := '';
          end;
        end
        else
        begin
          ShortName := '';
        end;

        Form2.StringGridConnectedDevices.RowCount :=
          Form2.StringGridConnectedDevices.RowCount + 1;
        Form2.StringGridConnectedDevices.Cells[0,
          Form2.StringGridConnectedDevices.RowCount - 1] := parts[0];
        Form2.StringGridConnectedDevices.Cells[1,
          Form2.StringGridConnectedDevices.RowCount - 1] := parts[1];
        Form2.StringGridConnectedDevices.Cells[2,
          Form2.StringGridConnectedDevices.RowCount - 1] := longname;
      end;
      for i := 0 to Form2.StringGridConnectedDevices.ColCount - 1 do
        Form2.StringGridConnectedDevices.AutoSizeColumn(i);
      Form2.StringGridConnectedDevices.PopupMenu := Form2.PopupMenuCopy;

    finally
      button5.Caption := 'Show Connected Devices';
    end;

    connectedDevices.Free;
    Form2.ShowModal;
  end
  else
  begin
    ShowMessage('Select an interface!');
  end;
end;







function TifOutErrors.LookupMAC(macPrefix: string; out ShortName, LongName: string;
  dbname: string): boolean;
var
  dbConnection: TSQLite3Connection;
  sqlTransaction: TSQLTransaction;
  sqlCommand: TSQLQuery;

begin
  ShortName := '';
  LongName := '';
  Result := False;

  // Initialize database connection
  dbConnection := TSQLite3Connection.Create(nil);
  sqlTransaction := TSQLTransaction.Create(dbConnection);
  sqlCommand := TSQLQuery.Create(nil);

  try
    dbConnection.DatabaseName := dbname; // Set your database path
    dbConnection.Connected := True;
    sqlCommand.Database := dbConnection;
    sqlCommand.Transaction := sqlTransaction;
    sqlTransaction.Database := dbConnection;
    sqlTransaction.StartTransaction;

    // showmessage(macprefix);

 sqlCommand.SQL.Text := 'SELECT short_name, full_name FROM mac_addresses ' +
                       'WHERE :macPrefix LIKE prefix || ''%'' ' +
                       'ORDER BY LENGTH(prefix) DESC LIMIT 1;';

sqlCommand.ParamByName('macPrefix').AsString := macPrefix;

sqlCommand.Open;


//showmessage( sqlCommand.SQL.Text);


  {  madd6 := Copy(macPrefix, 1, 6);
    madd8 := Copy(macPrefix, 1, 8);
    madd10 := Copy(macPrefix, 1, 10);

    // Prepare and execute SQL command
    sqlCommand.SQL.Text := 'SELECT short_name, full_name FROM mac_addresses ' +
      'WHERE (( prefix = :prefix6) OR (prefix = :prefix8) OR (prefix = :prefix10)) ' +
      'ORDER BY LENGTH(prefix) DESC LIMIT 1;';
    sqlCommand.ParamByName('prefix6').AsString := madd6;
    sqlCommand.ParamByName('prefix8').AsString := madd8;
    sqlCommand.ParamByName('prefix10').AsString := madd10;
    sqlCommand.Open;}

    if not sqlCommand.EOF then
    begin
      ShortName := sqlCommand.FieldByName('short_name').AsString;
      LongName := sqlCommand.FieldByName('full_name').AsString;
      Result := True; // Indicate that a record was found
    end;

   // sqlTransaction.Commit;
  finally
    sqlCommand.Free;
    sqlTransaction.Free;
    dbConnection.Free;
  end;
end;



// Function to format the MAC address
function TifOutErrors.FormatMacAddress(macAddress: string): string;
var
  i: integer;
begin
  Result := '';
  for i := 1 to Length(macAddress) do
  begin
    Result := Result + Format('%d', [Ord(macAddress[i])]);
    if (i mod 2 = 0) and (i < Length(macAddress)) then
      Result := Result + '.';
  end;
end;

// Function to format the IP address
function TifOutErrors.FormatIPAddress(ipAddress: string): string;
var
  octets: array of string;
  i: integer;
begin
  octets := SplitString(ipAddress, '.');
  Result := '';
  for i := 0 to Length(octets) - 1 do
  begin
    if i > 0 then
      Result := Result + '.';
    Result := Result + octets[i];
  end;
end;

procedure TifOutErrors.dropdownChange(Sender: TObject);
begin
  timer1.Enabled := False;
  button1.Enabled := True;
end;




function TifOutErrors.HexToDec(const Hex: string): integer;
begin
  Result := StrToInt('$' + Hex);
end;

function TifOutErrors.MACAddressToDecimal(const MACAddress: string): string;
var
  HexOctets: TStringList;
  DecimalOctets: TStringList;
  i: integer;
begin
  // Split the MAC address into octets
  HexOctets := TStringList.Create;
  DecimalOctets := TStringList.Create;
  try
    HexOctets.Delimiter := '-';
    HexOctets.DelimitedText := MACAddress;

    // Convert each octet from hexadecimal to decimal
    for i := 0 to HexOctets.Count - 1 do
    begin
      DecimalOctets.Add(IntToStr(HexToDec(HexOctets[i])));
    end;

    // Concatenate the decimal octets with dots
    Result := StringReplace(DecimalOctets.Text, sLineBreak, '.', [rfReplaceAll]);
    // Remove the trailing dot if present
    Result := TrimRightSet(Result, ['.']);
  finally
    HexOctets.Free;
    DecimalOctets.Free;
  end;
end;

function TifOutErrors.StrToHexStr(const s: string): string;
var
  i: integer;
begin
  // Implement the StrToHexStr function to convert a string to its hexadecimal representation
  Result := '';
  for i := 1 to Length(s) do
    Result := Result + IntToHex(Ord(s[i]), 2);
end;

procedure TifOutErrors.CalculatePacketRateForAllSeries(Chart2: TChart);
var
  i, j: integer;
  Series: TLineSeries;
  PreviousValues: array of double;
  PacketRate: double;
  MaxValue: double;
begin
  MaxValue := 4294967295; // Maximum value for 32-bit counter

  // Initialize the PreviousValues array with the first data point of each series
  SetLength(PreviousValues, Chart2.SeriesCount);
  for j := 0 to Chart2.SeriesCount - 1 do
  begin
    Series := TLineSeries(Chart2.Series[j]);
    PreviousValues[j] := Series.YValue[0];
  end;

  // Iterate through each series on Chart1
  for j := 0 to Chart2.SeriesCount - 1 do
  begin
    // Assuming you have line series on Chart1
    Series := TLineSeries(Chart2.Series[j]);

    // Iterate through the data points in the series
    for i := 1 to Series.Count - 1 do
    begin
      // Check if the current value is equal to the previous value
      if Series.YValue[i] = PreviousValues[j] then
      begin
        // If there is no change, set the packet rate to 0
        PacketRate := 0;
      end
      else
      begin
        // Calculate the packet rate based on the difference between the current and previous values
        if Series.YValue[i] < PreviousValues[j] then
        begin
          PacketRate := Series.YValue[i] + (MaxValue - PreviousValues[j]);
        end
        else
        begin
          PacketRate := Series.YValue[i] - PreviousValues[j];
        end;
      end;

      // Update the packet rate for the current series in the corresponding edit box
      case j of
        0: EditIFInOctets.Text := FormatFloat('#,##0', PacketRate);
        1: EditIFOutOctets.Text := FormatFloat('#,##0', PacketRate);
        2: EditIFInErrors.Text := FormatFloat('#,##0', PacketRate);
        3: EditIFOutErrors.Text := FormatFloat('#,##0', PacketRate);
      end;

      // Update the previous value for the current series
      PreviousValues[j] := Series.YValue[i];
    end;
  end;
end;
 procedure TifOutErrors.Button6Click(Sender: TObject);
 begin
    formblackhole.ShowModal;
    end;


end.
