unit Unit2;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, Grids, Menus,clipbrd;

type

  { TForm2 }

  TForm2 = class(TForm)
    MenuItem1: TMenuItem;
    PopupMenuCopy: TPopupMenu;
    StringGridConnectedDevices: TStringGrid;
    procedure MenuItem1Click(Sender: TObject);
  private

  public

  end;

var
  Form2: TForm2;

implementation

{$R *.lfm}

{ TForm2 }

procedure TForm2.MenuItem1Click(Sender: TObject);

  var
  R, C: Integer;
  S: string;
begin
  S := '';
  for R := StringGridConnectedDevices.Selection.Top to StringGridConnectedDevices.Selection.Bottom do
  begin
    for C := StringGridConnectedDevices.Selection.Left to StringGridConnectedDevices.Selection.Right do
    begin
      if C > StringGridConnectedDevices.Selection.Left then
        S := S + #9; // Append a tab character as a separator between cells
      S := S + StringGridConnectedDevices.Cells[C, R];
    end;
    S := S + LineEnding; // Append a line break after each row
  end;
  Clipboard.AsText := S;
end;
end.

