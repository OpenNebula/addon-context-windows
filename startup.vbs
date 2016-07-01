strComputer = "."
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
Set fso = CreateObject("Scripting.FileSystemObject")

Set colDisks = objWMIService.ExecQuery("Select * from Win32_LogicalDisk Where VolumeName = 'CONTEXT'")

For Each objDisk in colDisks
    driveLetter = objDisk.Name
    Exit For
Next
 
If IsEmpty(driveLetter) Then
    driveLetter = "C:"
End If
 
contextPath = driveLetter & "\context.ps1"

If fso.FileExists(contextPath) Then
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run("powershell -NonInteractive -NoProfile -NoLogo -ExecutionPolicy Unrestricted -file " & contextPath)
End If
