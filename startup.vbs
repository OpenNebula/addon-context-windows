Set objShell = CreateObject("Wscript.Shell")
objShell.Run("powershell -NonInteractive -NoProfile -NoLogo -ExecutionPolicy Unrestricted -file D:\one-context.ps1")
Dim objFSO, objFolder
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFolder = objFSO.CreateFolder("C:\executedVBScript")
