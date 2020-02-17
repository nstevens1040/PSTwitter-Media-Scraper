$wscript = [System.Activator]::createInstance(
    [type]::getTypeFromCLSID(
        [GUID]::Parse('{72C24DD5-D70A-438B-8A42-98424B88AFB8}')
    )
)
$lnk = $wscript.CreateShortcut("$($ENV:USERPROFILE)\Desktop\Twitter Media Scraper.lnk")
$lnk.TargetPath = "$($PSHOME)\PowerShell.exe"
$lnk.Arguments = "-noexit -noprofile -nologo -ep remotesigned -f `"$($PWD.Path)\Twitter Media Scraper .ps1`""
$lnk.WorkingDirectory =  "$($PSHOME)"
$lnk.Save()
