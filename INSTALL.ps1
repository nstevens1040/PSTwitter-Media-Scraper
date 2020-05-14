
    $STARTPATH = "$($PWD.Path)"
    $CDIR = "$([System.IO.FileInfo]::New($MyInvocation.MyCommand.Path).Directory.FullName)"
    cd $CDIR
    if(!$PWD.Path.Contains("PSTwitter-Media-Scraper")){
        write-host "This script is not in the correct folder!" -ForegroundColor Red
    } else {
        $ReposFiles = @(git ls-files).Where({$_ -ne 'LICENSE'})
        $LocalFiles = @()
        @([System.IO.Directory]::GetFiles("$($pwd.Path)","*.*",[System.IO.SearchOption]::AllDirectories)).Where({[System.IO.FileInfo]::new($_).Extension -in (".dll",".cs",".gif",".pdb",".ps1",".dll",".md",".xml")}).ForEach({
            $LocalFiles += $_ -replace "$([System.Text.RegularExpressions.Regex]::Escape("$($PWD.Path)"))\\",'' -replace "\\",'/'
        })
        while(Compare-Object $ReposFiles $LocalFiles){
            if($PWD.Path -ne $CDIR){ cd $CDIR }
            write-host "Local repository is out of date!`n" -ForegroundColor Red
            write-host "In order for this solution to work correctly, the local repository must be up to date.`n" -ForegroundColor Yellow
            Write-Host "Delete the contents of:`n" -ForegroundColor Yellow
            Write-Host "`t$($CDIR)`n" -ForegroundColor Green
            write-host "and reset the local repo for: " -ForeGroundColor Yellow -NoNewLine
            write-host "PSTwitter-Media-Scraper" -ForeGroundColor Blue -NoNewLine
            Write-host " ?" -foregroundcolor yellow -NoNewLine
            Write-host " (y/n)" -ForegroundColor White -NoNewline
            $ans = read-host
            if($ans -eq 'y'){
                if($MyInvocation.MyCommand.Path){
                    $null = ([System.Diagnostics.Process]@{
                        StartInfo = [System.Diagnostics.ProcessStartInfo]@{
                            File = "$($PSHOME)\PowerShell.exe";
                            Arguments = " -ep RemoteSigned -noprofile -nologo -c cd '$($CDIR)'; iex (irm 'https://raw.githubusercontent.com/nstevens1040/PSTwitter-Media-Scraper/master/INSTALL.ps1')"
                        };
                    }).Start()
                } else {
                    gci -Recurse | Remove-Item -Recurse -Force
                    git reset --hard origin/master
                    $ReposFiles = @(git ls-files).Where({$_ -ne 'LICENSE'})
                    $LocalFiles = @()
                    @([System.IO.Directory]::GetFiles("$($pwd.Path)","*.*",[System.IO.SearchOption]::AllDirectories)).Where({[System.IO.FileInfo]::new($_).Extension -in (".dll",".cs",".gif",".pdb",".ps1",".dll",".md",".xml")}).ForEach({
                        $LocalFiles += $_ -replace "$([System.Text.RegularExpressions.Regex]::Escape("$($PWD.Path)"))\\",'' -replace "\\",'/'
                    })
                }
            }
            sleep -s 1
        }
    }
    if([System.IO.Directory]::GetFiles("$($PWD.Path)","Microsoft.VisualBasic.dll",[System.IO.SearchOption]::AllDirectories)){
        add-type -path "$([System.IO.Directory]::GetFiles("$($PWD.Path)","Microsoft.VisualBasic.dll",[System.IO.SearchOption]::AllDirectories))"
    }
    Function CreateDesktopShortcut
    {
        $wscript = [System.Activator]::createInstance(
            [type]::getTypeFromCLSID(
                [GUID]"72C24DD5-D70A-438B-8A42-98424B88AFB8"
            )
        )
        $lnk = $wscript.CreateShortcut("$($ENV:USERPROFILE)\Desktop\Twitter Media Scraper.lnk")
        $lnk.TargetPath = "$($PSHOME)\PowerShell.exe"
        $lnk.Arguments = "-noexit -noprofile -nologo -ep remotesigned -f `"$($PWD.Path)\Twitter Media Scraper .ps1`""
        $lnk.WorkingDirectory =  "$($PSHOME)"
        $lnk.Save()
    }
    
    Function SeletCustomFolder
    {
        Add-Type -AssemblyName System.Windows.Forms
        $PICKER = [System.Windows.Forms.FolderBrowserDialog]::new()
        $PICKER.RootFolder = "Desktop"
        $PICKER.ShowNewFolderButton = $true
        $null = $PICKER.ShowDialog()
        return "$($PICKER.SelectedPath)"
    }
    Function SetEnvVarFolder
    {
        Param(
            [string]$FOLDER,
            [string]$VARIABLE_NAME
        )
        if(![System.IO.Directory]::Exists($FOLDER)){ $null = [System.IO.Directory]::CreateDirectory($FOLDER) }
        $null = ([System.Diagnostics.Process]@{
            StartInfo = [System.Diagnostics.ProcessStartInfo]@{
                FileName = "$($PSHOME)\PowerShell.exe";
                Arguments = " -WindowStyle Hidden -noprofile -nologo -ep RemoteSigned -c [System.Environment]::SetEnvironmentVariable('$($VARIABLE_NAME)','$($FOLDER)','MACHINE')";
                Verb = "RunAs";
                WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden;
            }
        }).Start()
    }
    $TWBINROOT = $CDIR
    if([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE")){
        Switch(
            [microsoft.visualbasic.Interaction]::MsgBox(
                "Repository root folder seems to have been already set!`n`nClick 'Yes' to continue with environment variable:`n`n`t%TWBINROOT%`nset to:`n`t'$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))'`n`nClick 'No' to select another folder.",
                [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                "TWITTER MEDIA SCRAPER"
            )
        ){
            "Yes" { }
            "No" {
                $ans = "No"
                While($ans -eq "No"){
                    $TWBINROOT = SeletCustomFolder
                    $ans = [microsoft.visualbasic.Interaction]::MsgBox(
                        "Click 'Yes' to set environment variable:`n`n`t%TWBINROOT%`nto:`n`t'$($TWBINROOT)'`n`nClick 'No' to select another folder.",
                        [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                        "TWITTER MEDIA SCRAPER"
                    )
                }
                if($ans -eq "Yes"){
                    While([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE") -ne $TWBINROOT){
                        SetEnvVarFolder -FOLDER $TWBINROOT -VARIABLE_NAME 'TWBINROOT'
                        sleep -s 1
                    }
                }
            }
        }
    } else {
        Switch(
            [microsoft.visualbasic.Interaction]::MsgBox(
                "We'll need to set an environment variable that points to the location of the PSTwitter-Media-Scraper local repository.`n`nClick 'Yes' to set environment variable:`n`n`t%TWBINROOT%`nto:`n`t'$($TWBINROOT)'`n`nClick 'No' to select another folder.",
                [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                "TWITTER MEDIA SCRAPER"
            )
        ){
            "Yes" {
                While(![System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE")){
                    SetEnvVarFolder -FOLDER $TWBINROOT -VARIABLE_NAME 'TWBINROOT'
                    sleep -s 1
                }
            }
            "No" {
                $ans = "No"
                While($ans -eq "No"){
                    $TWBINROOT = SeletCustomFolder
                    $ans = [microsoft.visualbasic.Interaction]::MsgBox(
                        "Click 'Yes' to set environment variable:`n`n`t%TWBINROOT%`nto:`n`t'$($TWBINROOT)'`n`nClick 'No' to select another folder.",
                        [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                        "TWITTER MEDIA SCRAPER"
                    )
                }
                if($ans -eq "Yes"){
                    While(![System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE")){
                        SetEnvVarFolder -FOLDER $TWBINROOT -VARIABLE_NAME 'TWBINROOT'
                        sleep -s 1
                    }
                }
            }
        }
    }
    $TWDOWNLOAD = "$([System.Environment]::GetEnvironmentVariable('TWBINROOT','MACHINE'))\Download"
    if([System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE")){
        Switch(
            [microsoft.visualbasic.Interaction]::MsgBox(
                "Download folder seems to have been already set!`n`nClick 'Yes' to continue with environment variable:`n`n`t%TWDOWNLOAD%`nset to:`n`t'$([System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE"))'`n`nClick 'No' to select another folder.",
                [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                "TWITTER MEDIA SCRAPER"
            )
        ){
            "Yes" { }
            "No" {
                $ans = "No"
                While($ans -eq "No"){
                    $TWDOWNLOAD = SeletCustomFolder
                    $ans = [microsoft.visualbasic.Interaction]::MsgBox(
                        "Click 'Yes' to set environment variable:`n`n`t%TWDOWNLOAD%`nto:`n`t'$($TWDOWNLOAD)'`n`nClick 'No' to select another folder.",
                        [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                        "TWITTER MEDIA SCRAPER"
                    )
                }
                if($ans -eq "Yes"){
                    While([System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE") -ne $TWDOWNLOAD){
                        SetEnvVarFolder -FOLDER $TWDOWNLOAD -VARIABLE_NAME 'TWDOWNLOAD'
                        sleep -s 1
                    }
                }
            }
        }
    } else {
        Switch(
            [microsoft.visualbasic.Interaction]::MsgBox(
                "Now we'll need to set a download folder.`n`nClick 'Yes' to set environment variable:`n`n`t%TWDOWNLOAD%`nto:`n`t'$($TWDOWNLOAD)'`n`nClick 'No' to set a different download folder.",
                [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                "TWITTER MEDIA SCRAPER"
            )
        ){
            "Yes" {
                While(![System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE")){
                    SetEnvVarFolder -FOLDER $TWDOWNLOAD -VARIABLE_NAME 'TWDOWNLOAD'
                    sleep -s 1
                }
            }
            "No" {
                $ans = "No"
                While($ans -eq "No"){
                    $TWDOWNLOAD = SeletCustomFolder
                    $ans = [microsoft.visualbasic.Interaction]::MsgBox(
                        "Click 'Yes' to set environment variable:`n`n`t%TWDOWNLOAD%`nto:`n`t'$($TWDOWNLOAD)'`n`nClick 'No' to set a different download folder.",
                        [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                        "TWITTER MEDIA SCRAPER"
                    )
                }
                if($ans -eq "Yes"){
                    While(![System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE")){
                        SetEnvVarFolder -FOLDER $TWDOWNLOAD -VARIABLE_NAME 'TWDOWNLOAD'
                        sleep -s 1
                    }
                }
            }
        }
    }
    Switch(
        [microsoft.visualbasic.Interaction]::MsgBox(
            "Create a Desktop shortcut?",
            [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
            "TWITTER MEDIA SCRAPER"
        )
    ){
        "Yes" {
            CreateDesktopShortcut
        }
        "No" {}
    }
    cd $STARTPATH
    
