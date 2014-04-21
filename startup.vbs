strComputer = "."

Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")

Set colItems = objWMIService.ExecQuery _
    ("Select * From Win32_LogicalDisk Where VolumeName = 'CONTEXT'")

Dim driveLetter

For Each objItem in colItems
    driveLetter = objItem.Name
    Exit For
Next

If Len(driveLetter) Then
    contextPath = driveLetter & "\context.ps1"
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run("powershell -NonInteractive -NoProfile -NoLogo -ExecutionPolicy Unrestricted -file " & contextPath)
End If
