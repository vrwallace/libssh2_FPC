program project1;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, Unit1, tachartlazaruspkg, unit2, unit3
  { you can add units after this };

{$R *.res}

begin
  RequireDerivedFormResource:=True;
  Application.Title:='SMP Switch Metrics';
  Application.Initialize;
  Application.CreateForm(TifOutErrors, ifOutErrors);
  Application.CreateForm(TForm2, Form2);
  Application.CreateForm(Tformblackhole, formblackhole);
  Application.Run;
end.

