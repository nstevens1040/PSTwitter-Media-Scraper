$STARTPATH = "$($PWD.Path)"
if($MyInvocation.MyCommand.Path){
    $GLOBAL:CDIR = "$([System.IO.FileInfo]::New($MyInvocation.MyCommand.Path).Directory.FullName)"
    cd $GLOBAL:CDIR
} else {
    $GLOBAL:CDIR = "$($PWD.Path)"
}
Function Check-Env
{
    Param(
        [string]$TARGET_URI
    )
    if(![System.Environment]::GetEnvironmentVariable('TWBINROOT','MACHINE')){
        Write-host "Missing needed environment variable:`n" -foregroundcolor yellow
        write-host "`t%TWBINROOT%" -ForegroundColor green
    }
    if(![System.Environment]::GetEnvironmentVariable('TWDOWNLOAD','MACHINE')){
        write-host "`n`tand`n" -foregroundcolor yellow
        write-host "`t%TWDOWNLOAD%`n" -foregroundcolor green
    }
    if(![System.Environment]::GetEnvironmentVariable('TWDOWNLOAD','MACHINE') -or ![System.Environment]::GetEnvironmentVariable('TWBINROOT','MACHINE')){
        write-host "Run " -foregroundcolor Green -NoNewLine
        write-host "INSTALL.ps1" -foregroundcolor Blue -NoNewLine
        write-host "(y/n): " -foregroundcolor white -NoNewLine
        $ans = Read-Host
        if($ans -eq 'y'){
            $null = ([System.Diagnostics.Process]@{
                StartInfo = [System.Diagnostics.ProcessStartInfo]@{
                    FileName = "$($PSHOME)\PowerShell.exe";
                    Arguments = " -NoExit -ep RemoteSigned -noprofile -nologo -c cd " + "'$($GLOBAL:CDIR)'" + "; iex (irm "+"'https://raw.githubusercontent.com/nstevens1040/PSTwitter-Media-Scraper/master/INSTALL.ps1'" + "); Install-PSTwitterMediaScraper -TARGET_URI "+"'$($TARGET_URI)'";
                };
            }).Start()
            (Get-Process -Id $PID).kill()
        }
    }
    if(!$PWD.Path.Contains("PSTwitter-Media-Scraper")){
        write-host "This script is not in the correct folder!" -ForegroundColor Red
    } else {
        $ReposFiles = @(. "C:\Program Files\Git\bin\git.exe" ls-files).Where({$_ -ne 'LICENSE'})
        $LocalFiles = @()
        @([System.IO.Directory]::GetFiles("$($pwd.Path)","*.*",[System.IO.SearchOption]::AllDirectories)).Where({[System.IO.FileInfo]::new($_).Extension -in (".dll",".cs",".gif",".pdb",".ps1",".dll",".md",".xml")}).ForEach({
            $LocalFiles += $_ -replace "$([System.Text.RegularExpressions.Regex]::Escape("$($PWD.Path)"))\\",'' -replace "\\",'/'
        })
        while(Compare-Object $ReposFiles $LocalFiles){
            if($PWD.Path -ne $GLOBAL:CDIR){ cd $GLOBAL:CDIR }
            if($MyInvocation.MyCommand.Path){
                write-host "INSTALL.ps1" -ForegroundColor blue -nonewline
                write-host " was launched locally. To update the local repository, this file must not be in use." -foregroundcolor green
                write-host "Launch new process?" -foregroundcolor yellow -NoNewLine
                Write-host "(y/n): " -ForeGroundColor White -NoNewLine
                $ans = Read-Host
                if($ans -eq 'y'){
                    $null = ([System.Diagnostics.Process]@{
                        StartInfo = [System.Diagnostics.ProcessStartInfo]@{
                            FileName = "$($PSHOME)\PowerShell.exe";
                            Arguments = " -NoExit -ep RemoteSigned -noprofile -nologo -c cd " + "`"$($GLOBAL:CDIR)`"" + "; iex (irm "+"`"https://raw.githubusercontent.com/nstevens1040/PSTwitter-Media-Scraper/master/INSTALL.ps1`"" + "); Install-PSTwitterMediaScraper -TARGET_URI "+"`"$($TARGET_URI)`"";
                        };
                    }).Start()
                    (Get-Process -Id $PID).kill()
                }
            } else {
                write-host "Local repository is out of date!`n" -ForegroundColor Red
                write-host "In order for this solution to work correctly, the local repository must be up to date.`n" -ForegroundColor Yellow
                Write-Host "Delete the contents of:`n" -ForegroundColor Yellow
                Write-Host "`t$($GLOBAL:CDIR)`n" -ForegroundColor Green
                write-host "and reset the local repo for: " -ForeGroundColor Yellow -NoNewLine
                write-host "PSTwitter-Media-Scraper" -ForeGroundColor Blue -NoNewLine
                Write-host " ?" -foregroundcolor yellow -NoNewLine
                Write-host " (y/n)" -ForegroundColor White -NoNewline
                $ans = read-host
                if($ans -eq 'y'){
                    gci -Recurse | Remove-Item -Recurse -Force
                    . "C:\Program Files\Git\bin\git.exe" reset --hard origin/master
                    $ReposFiles = @(. "C:\Program Files\Git\bin\git.exe" ls-files).Where({$_ -ne 'LICENSE'})
                    $LocalFiles = @()
                    @([System.IO.Directory]::GetFiles("$($pwd.Path)","*.*",[System.IO.SearchOption]::AllDirectories)).Where({[System.IO.FileInfo]::new($_).Extension -in (".dll",".cs",".gif",".pdb",".ps1",".dll",".md",".xml")}).ForEach({
                        $LocalFiles += $_ -replace "$([System.Text.RegularExpressions.Regex]::Escape("$($PWD.Path)"))\\",'' -replace "\\",'/'
                    })
                }
            }
            sleep -s 1
        }
    }
    #Scrape-Page -TARGET_URI $TARGET_URI
}
function Start-IE
{
    param()
    Add-Type -AssemblyName Microsoft.VisualBasic
    While(!$test){
        try {
            $test = iwr google.com -ea 0 -Method Head
        }
        catch [System.NotSupportedException]{
            if(!$ans){
                $ans = [Microsoft.VisualBasic.Interaction]::MsgBox(
                    "You will need to open Internet Explorer and complete the 'first run' wizard.",
                    [Microsoft.VisualBasic.MsgBoxStyle]::OkOnly,
                    "Twitter Web Scraping Machine"
                )
            }
            if(!$iexplore){
                . "C:\program files\internet Explorer\iexplore.exe"
                While((Get-Process iexplore -ea 0)){
                    sleep -m 200
                }
                $iexplore = $true
            }
        }
    }
}
function Install-7Z
{
    param()
    if(![System.IO.File]::Exists("C:\Program Files\7-Zip\7z.exe") -and ![System.IO.File]::Exists("$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))\7-zip\7z.exe")){
        Write-Host "Installing 7-zip ..." -ForegroundColor Yellow
        $r = iwr "https://www.7-zip.org/download.html"
        $URI = @(@($r.ParsedHtml.getElementsByTagName("A")).Where({ $_.href -match "-x64.msi" }) | % href).ForEach({ $_ -replace "about:","https://7-zip.org/" })[0]
        $FILE = "$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))\INSTALLERS\$((@(@($r.ParsedHtml.getElementsByTagName("A")).Where({$_.href -match "-x64.msi"}) | % href).ForEach({$_ -replace "about:","https://7-zip.org/"})[0]).split("/")[-1])"
        if(![System.IO.Directory]::Exists("$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))\INSTALLERS")){
            $null = [System.IO.Directory]::CreateDirectory("$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))\INSTALLERS")
        }
        if(![System.IO.Directory]::Exists("$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))\7-zip\")){
            $null = [System.IO.Directory]::CreateDirectory("$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))\7-zip\")
        }
        ([System.Net.WebClient]@{ Proxy = $null }).DownloadFile(
            $URI,
            $FILE
        )
        if([System.IO.File]::Exists("$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))\INSTALLERS\$((@(@($r.ParsedHtml.getElementsByTagName("A")).Where({$_.href -match "-x64.msi"}) | % href).ForEach({$_ -replace "about:","https://7-zip.org/"})[0]).split("/")[-1])")){
            cmd /c "msiexec /i `"$($FILE)`" INSTALLDIR=$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))\7-zip\ MSIINSTALLPERUSER=1 /qb /norestart"
        }
    } else {
        Write-Host "7-zip is already installed" -ForegroundColor Yellow
    }
}
function RelCom
{
    param($ComObject)
    $ret = 1
    While($ret -gt 0){
        try {
            $ret = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($comobject)
        }
        catch [System.Management.Automation.MethodInvocationException]{
            break
        }
    }
}
function AddAllAssemblies
{
    param()
    @([System.IO.Directory]::GetFiles("$([System.Environment]::GetEnvironmentVariable("TWBINROOT","MACHINE"))\Assemblies","*.dll",[System.IO.SearchOption]::AllDirectories)).ForEach({Add-Type -Path $_})
}
function SetConsoleOptions
{
    param()
    [System.Console]::BackgroundColor = "Black"
    [System.Console]::Clear()
    $HOST.ui.RawUI.WindowTitle = "Welcome to my Twitter scraping machine!!"
    MoveWindowOver -SIDE 'RIGHT' -THIS_WINDOW; sleep -s 2; [System.Console]::BufferWidth = 1000; [System.Console]::Clear();
    Write-Host "`n"
    Write-Host @"
      _______       _ _   _             __          __  _        _____                                
     |__   __|     (_) | | |            \ \        / / | |      / ____|                               
        | |_      ___| |_| |_ ___ _ __   \ \  /\  / /__| |__   | (___   ___ _ __ __ _ _ __   ___ _ __ 
        | \ \ /\ / / | __| __/ _ \ '__|   \ \/  \/ / _ \ '_ \   \___ \ / __| '__/ _`` | '_ \ / _ \ '__|
        | |\ V  V /| | |_| ||  __/ |       \  /\  /  __/ |_) |  ____) | (__| | | (_| | |_) |  __/ |   
        |_| \_/\_/ |_|\__|\__\___|_|        \/  \/ \___|_.__/  |_____/ \___|_|  \__,_| .__/ \___|_|   
                                                                                     | |              
                                                                                     |_|              
"@ -ForegroundColor Yellow
    Write-Host "`n"
}
function CheckAuthGetUser
{
    param(
        [string]$HTMLRESPONSETEXT
    )
    return ([System.Text.RegularExpressions.Regex]::new("\{\`"(.+)\}")).Match(
        @($HTMLRESPONSETEXT.split("`n")).Where({ $_ -match "responsive_web_graphql_verify_credentials_enabled" })
    ).Value |
    ConvertFrom-Json |
    % entities |
    % users |
    % entities |
    % (([System.Text.RegularExpressions.Regex]::new("\{\`"(.+)\}")).Match(
            @($HTMLRESPONSETEXT.split("`n")).Where({ $_ -match "responsive_web_graphql_verify_credentials_enabled" })
        ).Value |
        ConvertFrom-Json |
        % entities |
        % users |
        % entities |
        gm -MemberType NoteProperty -ea 0 | % Name) | % Name
}
function MoveWindowOver
{
    param(
        [ValidateSet('LEFT','RIGHT')]
        [string]$SIDE,
        [switch]$THIS_WINDOW,
        [int32]$PROCESSID,
        [int32]$MAINWINDOWHANDLE
    )
    if($THIS_WINDOW){
        @(2,3).ForEach({
                $null = [NativeM.Win32]::ShowWindowAsync((Get-Process -Id $PID).MainWindowHandle,$_)
            })
        $RECT = New-Object NativeM.RECT
        $null = [NativeM.Win32]::GetWindowRect((Get-Process -Id $PID -ea 0).MainWindowHandle,[ref]$RECT)
        $WID = ($RECT.Right - $RECT.Left)
        $HIG = $RECT.Bottom - $RECT.Top
        if($SIDE -eq 'LEFT'){
            $NLE = $RECT.Left
        }
        if($SIDE -eq 'RIGHT'){
            $NLE = $RECT.Left + ($WID / 2)
        }
        $NTO = $RECT.Top
        $null = [NativeM.Win32]::MoveWindow(
            (Get-Process -Id $PID -ea 0).MainWindowHandle,
            $NLE,
            $NTO,
            ($WID / 2),
            $HIG,
            $true
        )
    }
    if(!$THIS_WINDOW){
        if($PROCESSID){
            @(2,3).ForEach({
                    $null = [NativeM.Win32]::ShowWindowAsync((Get-Process -Id $PROCESSID -ea 0).MainWindowHandle,$_)
                })
            $RECT = New-Object NativeM.RECT
            $null = [NativeM.Win32]::GetWindowRect((Get-Process -Id $PROCESSID -ea 0).MainWindowHandle,[ref]$RECT)
            $WID = ($RECT.Right - $RECT.Left)
            $HIG = $RECT.Bottom - $RECT.Top
            if($SIDE -eq 'LEFT'){
                $NLE = $RECT.Left
            }
            if($SIDE -eq 'RIGHT'){
                $NLE = $RECT.Left + ($WID / 2)
            }
            $NTO = $RECT.Top
            $null = [NativeM.Win32]::MoveWindow(
                (Get-Process -Id $PROCESSID -ea 0).MainWindowHandle,
                $NLE,
                $NTO,
                ($WID / 2),
                $HIG,
                $true
            )
        }
        if($MAINWINDOWHANDLE){
            @(2,3).ForEach({
                    $null = [NativeM.Win32]::ShowWindowAsync($MAINWINDOWHANDLE,$_)
                })
            $RECT = New-Object NativeM.RECT
            $null = [NativeM.Win32]::GetWindowRect($MAINWINDOWHANDLE,[ref]$RECT)
            $WID = ($RECT.Right - $RECT.Left)
            $HIG = $RECT.Bottom - $RECT.Top
            if($SIDE -eq 'LEFT'){
                $NLE = $RECT.Left
            }
            if($SIDE -eq 'RIGHT'){
                $NLE = $RECT.Left + ($WID / 2)
            }
            $NTO = $RECT.Top
            $null = [NativeM.Win32]::MoveWindow(
                $MAINWINDOWHANDLE,
                $NLE,
                $NTO,
                ($WID / 2),
                $HIG,
                $true
            )
        }
    }
}

function WaitFor
{
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string]$TITLE,
        [int32]$PROCESSID
    )
    $ANIMATION = @()
    $stri = "___________________________________________________________"
    (0..68) | % {
        $ANIMATION += $stri;
        $a = New-Object system.collections.arraylist
        $stri.tochararray() | % { $a.Add($_) | Out-Null }
        if($_ -lt 10){
            $a[$_] = $a[$_] -replace '_',"#"
            $stri = $a -join ''
        }
        if($_ -ge 10 -and $_ -lt 59){
            $a[$_] = $a[$_] -replace "_","#"
            $a[($_ - 10)] = $a[($_ - 10)] -replace "`#","_"
            $stri = $a -join ''
        }
        if($_ -ge 59){
            $a[$_ - 10] = $a[$_ - 10] -replace "`#","_"
            $stri = $a -join ''
        }
    }
    Write-Host "`n"
    $BLANK = "`b" * ($TITLE.length + 60)
    $CLEAR = " " * ($TITLE.length + 60)
    $TOP = [Console]::CursorTop
    While(!(Get-Process -Id $PROCESSID -ea 0)){ sleep -m 100 }
    [Console]::CursorVisible = $false
    While(Get-Process -Id $PROCESSID -ea 0){
        $ANIMATION.ForEach({
                Write-Host $BLANK -NoNewline
                [console]::CursorTop = $top
                [console]::CursorLeft = 0
                Write-Host "$($TITLE) $($_)" -ForegroundColor Green -NoNewline
                sleep -m 20
            })
    }
    Write-Host "$($BLANK)$($CLEAR)$($BLANK)" -NoNewline
    Write-Host "`n"
    [Console]::CursorVisible = $true
}
function Get-TWBearerToken
{
    param(
        [switch]$SECONDARY
    )
    if($SECONDARY){
        $BEARER = [System.Convert]::ToBase64String(
            [System.Security.Cryptography.ProtectedData]::Protect(
                [System.Text.Encoding]::Unicode.GetBytes(
                    [Dialog.Prompt]::ShowDialog("Please paste your secondary Bearer token and click 'Ok'.","Twitter Scraping Machine")
                ),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    } else {
        $HEADERS = [ordered]@{
            "method" = "GET";
            "authority" = "ma-0.twimg.com";
            "scheme" = "https";
            "path" = "/twitter-assets/responsive-web/web/ltr/main.5b6bf12947d7a3a6.js";
            "pragma" = "no-cache";
            "cache-control" = "no-cache";
            "dnt" = "1";
            "upgrade-insecure-requests" = "1";
            "user-agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36";
            "sec-fetch-dest" = "document";
            "accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
            "sec-fetch-site" = "none";
            "sec-fetch-mode" = "navigate";
            "accept-encoding" = "gzip, deflate";
            "accept-language" = "en-US,en;q=0.9";
        }
        $MAINJS = Execute-WebRequest -Method 'GET' `
             -Headers $HEADERS `
             -NO_COOKIE `
             -Uri "https://ma-0.twimg.com/twitter-assets/responsive-web/web/ltr/main.5b6bf12947d7a3a6.js"
        $BEARER = [System.Convert]::ToBase64String(
            [System.Security.Cryptography.ProtectedData]::Protect(
                [System.Text.Encoding]::Unicode.GetBytes(
                    ([System.Text.RegularExpressions.Regex]::new("BEARER_TOKEN:`"|`"")).Replace(
                        $(([System.Text.RegularExpressions.Regex]::new("BEARER_TOKEN:`"(\w+)%(\w+)`"")).Match($MAINJS.ResponseText).Value),
                        ''
                    )
                ),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }
    return $BEARER
}
function Get-EncryptedCredentialString
{
    param()
    $CREDSTR = [System.Convert]::ToBase64String(
        [System.Security.Cryptography.ProtectedData]::Protect(
            [System.Text.Encoding]::Unicode.GetBytes(
                "$(@(@([WinCred.CredentialDialog]::AuthEasy()).ForEach({
                        [System.Convert]::ToBase64String(
                            [System.Text.Encoding]::Unicode.GetBytes("$($_)")
                        )
                    })) -join "$([char]167)")"
            ),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )
    return $CREDSTR
}
function Get-TWAuthenticityToken
{
    param(
        [System.Object[]]$FORMS
    )
    return "$($FORMS | % { $_ | select name,value } | ? {($_ | % Name) -eq 'authenticity_token'} | select -First 1 | % value)"
}
function MakeRequestBody
{
    param(
        [string]$JSON,
        [System.Object[]]$FORMS,
        [string]$ENCRYPTED_CRED_STRING
    )
    $CREDRA = @()
    @("$([System.Text.Encoding]::Unicode.GetString( [System.Security.Cryptography.ProtectedData]::Unprotect(
            [System.Convert]::FromBase64String($ENCRYPTED_CRED_STRING),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )))".split("$([char]167)")).ForEach({
            $CREDRA += [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("$($_)"))
        })
    $JSON = '{ "session%5Busername_or_email%5D": "' + "$($CREDRA[0])" + '", "session%5Bpassword%5D": "' + "$($CREDRA[1])" + '", "authenticity_token": "--MYAUTHTOKEN--", "ui_metrics": "{\"rf\":{\"ad555f04e4ce8d8ea891746a07bfff01728a2a430a7849ea2f48c8aa57359bcd\":-126,\"efc4b66122211ff0147e4b00547e3de404eb77851484f96e82b6605c8ff15b69\":-34,\"c093889af3de9f5e0c95c7c59869c2b1f01edb7f77a1c617466ce170c2fcb897\":-50,\"a8cfc052a2b3a68eadad84d9fe4cef8573e2fb109471909de2cf5076ee631597\":94},\"s\":\"ngvapRO7DD4WJliK96s1FZQut2lYw4wGpaNKrLJLM-agVPat99mFX56X6MV2wUNkhx_-a6skoaeEJSUzAnyWSn7lerF-LeVrHFRkZNzUvfJEZS-eHsFmBXZJEMZhco6B6juM-lVTC_pkfiUuxXljAWvJtpjQFNrd222NGPLxZRJTLzntzUW263derKQmfX_nqI0Xxo0-YZyjQgWhpRrpV6UEg8SM_7EVtC75xLzoDuk79KcW9KTaVRxRX-pfe5kLidkOQqLVEQbAKGIbshpBCeb4T6uRN_lcXT5Wcc61BJPZpUnJHSgFXQgFsIMPJ2TurxnFjubs1USdh0tQiFBgOgAAAWfRqJpX\"}", "scribe_log": "", "redirect_after_login": "", "authenticity_token_": "--MYAUTHTOKEN--", "remember_me": "1"}'
    $OBJ = $JSON -replace '--MYAUTHTOKEN--',"$(Get-TWAuthenticityToken -FORMS $FORMS)" | ConvertFrom-Json
    return [System.Convert]::ToBase64String(
        [System.Security.Cryptography.ProtectedData]::Protect(
            [System.Text.Encoding]::Unicode.GetBytes(
                "$("$(@(@(
                        'session%5Busername_or_email%5D',
                        'session%5Bpassword%5D',
                        'authenticity_token',
                        'ui_metrics',
                        'scribe_log',
                        'redirect_after_login',
                        'authenticity_token',
                        'remember_me'
                    ).forEach({
                        if($_ -in ("session%5Busername_or_email%5D","session%5Bpassword%5D")){
                            "&$($_)=$([uri]::EscapeDataString("$($OBJ | % "$($_)")"))"
                        } else {
                            "&$([uri]::EscapeDataString("$($_)"))=$([uri]::EscapeDataString("$($OBJ | % "$($_)")"))"
                        }
                    })) -join '')" -replace "^&",'')"
            ),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )
}
function MakeCookie
{
    param(
        [string]$JSON,
        [datetime]$EXPIRES
    )
    $OBJECT = $JSON | ConvertFrom-Json
    $cook1 = [System.Net.Cookie]::new()
    $cook1.Name = $OBJECT.Name
    $cook1.Value = $OBJECT.Value
    $cook1.Path = $OBJECT.Path
    $cook1.Domain = $OBJECT.Domain
    if($EXPIRES){
        $cook1.Expires = $EXPIRES
    }
    return $cook1
}
function Execute-WebRequest
{
    param(
        [ValidateSet('GET','POST','HEAD','OPTIONS')]
        [string]$METHOD,
        [string]$BODY,
        [string]$ENCRYPTEDBODY,
        [string]$BEARER,
        [string]$CSRF,
        $HEADERS,
        [string]$URI,
        $DEFAULTCOOKIES,
        [switch]$GOOGLEAPI,
        [string]$CONTENT_TYPE,
        [string]$REFERER,
        [switch]$NO_COOKIE,
        [switch]$GET_REDIRECT_URI
    )
    if($ENCRYPTEDBODY){
        $BODY = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.Convert]::FromBase64String($ENCRYPTEDBODY),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }
    if($CSRF){
        $CSRF = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.Convert]::FromBase64String($CSRF),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }
    if($BEARER){
        $BEARER_TOKEN = [System.Text.Encoding]::Unicode.GetString(
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                [System.Convert]::FromBase64String($BEARER),
                $null,
                [System.Security.Cryptography.DataProtectionScope]::LocalMachine
            )
        )
    }
    Write-Host "HTTP $($METHOD): " -ForegroundColor Yellow -NoNewline
    Write-Host "$($URI.Split('/')[2]) :: " -ForegroundColor Green -NoNewline
    Write-Host "/$($URI.Split('/')[3..($URI.Split('/').length)] -join '/') HTTP/1.1" -ForegroundColor Green
    $HANDLE = [System.Net.Http.HttpClientHandler]::new()
    $HANDLE.AutomaticDecompression = [System.Net.DecompressionMethods]::GZip,[System.Net.DecompressionMethods]::Deflate
    $HANDLE.SslProtocols = (
        [System.Security.Authentication.SslProtocols]::Tls,
        [System.Security.Authentication.SslProtocols]::Tls11,
        [System.Security.Authentication.SslProtocols]::Tls12
    )
    $HANDLE.UseProxy = $false
    $HANDLE.AllowAutoRedirect = $true
    $HANDLE.MaxAutomaticRedirections = 500
    $COOKIE = [System.Net.CookieContainer]::new()
    if($DEFAULTCOOKIES){
        if($DEFAULTCOOKIES.GetType() -eq [System.Net.CookieCollection]){
            $DEFAULTCOOKIES.ForEach({
                    $COOKIE.Add($_)
                })
        }
        if($DEFAULTCOOKIES.GetType() -eq [System.Collections.Hashtable]){
            if($GOOGLEAPI){
                $DEFAULTCOOKIES.Keys.ForEach({
                        $cook = [system.net.cookie]@{
                            Name = $_;
                            Value = $DEFAULTCOOKIES[$_];
                            Path = "/";
                            Domain = ".google.com"
                        }
                        $Cookie.Add($cook)
                    })
            }
            if(!$GOOGLEAPI){
                $DOMAIN = ".$([URI]::New($URI).Host)"
                $DEFAULTCOOKIES.Keys.ForEach({
                        $cook = [system.net.cookie]@{
                            Name = $_;
                            Value = $DEFAULTCOOKIES[$_];
                            Path = "/";
                            Domain = $DOMAIN;
                        }
                        $Cookie.Add($cook)
                    })
            }
        }
    }
    $HANDLE.CookieContainer = $COOKIE
    $CLIENT = [System.Net.Http.HttpClient]::new($HANDLE)
    if($BEARER){
        $null = $CLIENT.DefaultRequestHeaders.Add("authorization","Bearer $($BEARER_TOKEN)")
    }
    if($CSRF){
        $null = $CLIENT.DefaultRequestHeaders.Add("x-csrf-token","$($CSRF)")
    }
    if($HEADERS){
        if($HEADERS.GetType() -eq [System.Collections.Specialized.OrderedDictionary]){
            $HEADERS.Keys.ForEach({
                    if($CLIENT.DefaultRequestHeaders.Contains("$($_)")){
                        $null = $CLIENT.DefaultRequestHeaders.Remove("$($_)")
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add("$($_)","$($HEADERS["$($_)"])")
                })
        }
        if($HEADERS.GetType() -eq [System.Net.Http.Headers.HttpResponseHeaders]){
            $HEADERS.key.ForEach({
                    if($CLIENT.DefaultRequestHeaders.Contains("$($_)")){
                        $null = $CLIENT.DefaultRequestHeaders.Remove("$($_)")
                    }
                    $null = $CLIENT.DefaultRequestHeaders.Add("$($_)","$($HEADERS.getValues("$($_)"))")
                })
        }
    }
    if($CLIENT.DefaultRequestHeaders.Contains("Path")){
        $null = $CLIENT.DefaultRequestHeaders.Remove("Path")
    }
    $null = $CLIENT.DefaultRequestHeaders.Add("Path","/$($URI.Split('/')[3..($URI.Split('/').length)] -join '/')")
    if($REFERER){
        if($CLIENT.DefaultRequestHeaders.Contains("Referer")){
            $null = $CLIENT.DefaultRequestHeaders.Remove("Referer")
        }
        $null = $CLIENT.DefaultRequestHeaders.Add("Referer",$REFERER)
    }
    if($CONTENT_TYPE){
        $CLIENT.DefaultRequestHeaders.Accept.Add([System.Net.Http.Headers.MediaTypeWithQualityHeaderValue]::new("$($CONTENT_TYPE)"))
    }
    $OBJ = [psobject]::new()
    switch ($METHOD){
        "GET" {
            $RES = $CLIENT.GetAsync($URI)
            $S = $RES.Result.Content.ReadAsStringAsync()
            $HTMLSTRING = $S.Result
            $RESHEAD = $RES.Result.Headers
        }
        "POST" {
            if($CONTENT_TYPE){
                $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post,"$($URI)")
                $RM.Content = [System.Net.Http.StringContent]::new($BODY,[System.Text.Encoding]::UTF8,"$($CONTENT_TYPE)")
                $RES = $CLIENT.SendAsync($RM)
                $RESHEAD = $RES.Result.Headers
                $S = $RES.Result.Content.ReadAsStringAsync()
                $HTMLSTRING = $S.Result
            }
            if(!$CONTENT_TYPE){
                if(!$BODY){
                    $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post,"$($URI)")
                    $RM.Content = [System.Net.Http.StringContent]::new($null,[System.Text.Encoding]::UTF8,"application/x-www-form-urlencoded")
                    $RES = $CLIENT.SendAsync($RM)
                    $RESHEAD = $RES.Result.Headers
                    $S = $RES.Result.Content.ReadAsStringAsync()
                    $HTMLSTRING = $S.Result
                }
                if($BODY){
                    $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post,"$($URI)")
                    $RM.Content = [System.Net.Http.StringContent]::new($BODY,[System.Text.Encoding]::UTF8,"application/x-www-form-urlencoded")
                    $RES = $CLIENT.SendAsync($RM)
                    $RESHEAD = $RES.Result.Headers
                    $S = $RES.Result.Content.ReadAsStringAsync()
                    $HTMLSTRING = $S.Result
                }
            }
        }
        "HEAD" {
            $RM = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Head,"$($URI)")
            $RES = $CLIENT.SendAsync($RM)
            $RESHEAD = $RES.Result.Headers
        }
    }
    if(!$NO_COOKIE){
        $TO = [datetime]::Now
        While(
            !$HANDLE.CookieContainer.GetCookies($URI) -or `
                 (([datetime]::Now - $TO) | % totalSeconds) -lt 5
        ){ sleep -m 100 }
    }
    $COOKIES = $HANDLE.CookieContainer.GetCookies($URI)
    if($DEFAULTCOOKIES){
        @($DEFAULTCOOKIES.Where({
                    $_.Value -notin @($COOKIES.ForEach({ $_.Value }))
                })).ForEach({
                $COOKIES.Add($_)
            })
    }
    if($GET_REDIRECT_URI){
        $TO = [datetime]::Now
        While(
            !$RES.Result.RequestMessage.RequestUri.AbsoluteUri -or `
                 (([datetime]::Now - $TO) | % totalSeconds) -lt 5
        ){ sleep -m 100 }
        $REDIRECT = $RES.Result.RequestMessage.RequestUri.AbsoluteUri
    }
    if($HTMLSTRING){
        $DOMOBJ = [System.Activator]::CreateInstance([type]::getTypeFromCLSID([guid]::Parse("{25336920-03F9-11cf-8FD0-00AA00686F13}")))
        $DOMOBJ.IHTMLDocument2_write([System.Text.Encoding]::Unicode.GetBytes($HTMLSTRING))
    }
    if($GET_REDIRECT_URI){
        $OBJ | Add-Member -MemberType NoteProperty -Name RedirectUri -Value $REDIRECT
    }
    $OBJ | Add-Member -MemberType NoteProperty -Name HttpResponseMessage -Value $RES
    $OBJ | Add-Member -MemberType NoteProperty -Name CookieCollection -Value $COOKIES
    $OBJ | Add-Member -MemberType NoteProperty -Name HttpResponseHeaders -Value $RESHEAD
    if($HTMLSTRING){
        $OBJ | Add-Member -MemberType NoteProperty -Name HtmlDocument -Value $DOMOBJ
        $OBJ | Add-Member -MemberType NoteProperty -Name ResponseText -Value $HTMLSTRING
    }
    return $OBJ
}
Function Twitter-Login
{    
    [CmdletBinding()]
    param(
        [switch]$DONT_REENCODE_VIDEOS = $true
    )
    Start-IE
    AddAllAssemblies
    SetConsoleOptions
    if(!$BEARER_TOKEN){
        $BEARER_TOKEN = Get-TWBearerToken
    }

    $h = [ordered]@{
        "method" = "GET";
        "authority" = "api.twitter.com";
        "scheme" = "https";
        "pragma" = "no-cache";
        "cache-control" = "no-cache";
        "dnt" = "1";
        "x-twitter-client-language" = "en";
        "user-agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
        "sec-fetch-dest" = "empty";
        "x-twitter-auth-type" = "OAuth2Session";
        "x-twitter-active-user" = "yes";
        "accept" = "*/*";
        "origin" = "https://twitter.com";
        "sec-fetch-site" = "same-site";
        "sec-fetch-mode" = "cors";
        "accept-encoding" = "gzip, deflate";
        "accept-language" = "en-US,en;q=0.9"
    }
    
    #### LOGIN AUTH START ####
    While(!$USERNAME){
        $ECS = Get-EncryptedCredentialString
    
        $CK1 = '{ "Comment": "", "CommentUri": null, "HttpOnly": false, "Discard": false, "Domain": "twitter.com", "Expired": false, "Expires": "\/Date(-62135575200000)\/", "Name": "app_shell_visited", "Path": "/", "Port": "", "Secure": false, "TimeStamp": "\/Date(1578913791674)\/", "Value": "1", "Version": 0}'
        $CK2 = '{ "Comment": "", "CommentUri": null, "HttpOnly": false, "Discard": false, "Domain": ".twitter.com", "Expired": true, "Expires": "\/Date(1578913611000)\/", "Name": "fm", "Path": "/", "Port": "", "Secure": false, "TimeStamp": "\/Date(1578913791689)\/", "Value": "0", "Version": 0}'
    
        $WebHeaderCollection = @()
        $WebHeaderCollection += [ordered]@{
            "method" = "GET";
            "authority" = "twitter.com";
            "scheme" = "https";
            "path" = "/login";
            "upgrade-insecure-requests" = "1";
            "user-agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
            "accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
            "accept-encoding" = "gzip, deflate";
            "accept-language" = "en-US,en;q=0.9";
        }
        $WebHeaderCollection += [ordered]@{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
        }
        $WebHeaderCollection += [ordered]@{
            "pragma"="no-cache";
            "cache-control"="no-cache";
            "path" = "/sessions";
            "method" = "POST";
            "authority" = "twitter.com";
            "accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
            "user-agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
            "scheme" = "https";
            "accept-language" = "en-US,en;q=0.9";
            "accept-encoding" = "gzip, deflate";
            "upgrade-insecure-requests" = "1";
            "referer"="https://twitter.com/login";
            "sec-fetch-site"="same-origin";
            "sec-fetch-mode"="navigate";
            "sec-fetch-user"="?1";
            "sec-fetch-dest"="document";
            "dnt"="1";
            "origin"="https://twitter.com"
        }
        $WebHeaderCollection += [ordered]@{
            "path" = "/";
            "method" = "GET";
            "authority" = "twitter.com";
            "accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
            "user-agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36";
            "scheme" = "https";
            "accept-language" = "en-US,en;q=0.9";
            "accept-encoding" = "gzip, deflate";
            "upgrade-insecure-requests" = "1";
        }
    
        $LOGIN = Execute-WebRequest -Method GET `
             -Uri "https://twitter.com/login"
        $FORMS = @(); @($LOGIN.HtmlDocument.getElementsByTagName("FORM")).ForEach({ $FORMS += $_ })
    
        $UIMET = Execute-WebRequest -Method GET `
             -Uri "https://twitter.com/i/js_inst?c_name=ui_metrics"
        $EXPIRES = [datetime]"$(($UIMET.HttpResponseHeaders.GetValues("Set-Cookie").Split(';') | ? {$_ -match 'expires'} | select -First 1).split('=')[1])"
        $COOKIE1 = MakeCookie -JSON $CK1
        $COOKIE2 = MakeCookie -JSON $CK2 -EXPIRES $EXPIRES
        $BODY = MakeRequestBody -FORMS $FORMS -ENCRYPTED_CRED_STRING $ECS
        $COLLECT = [System.Net.CookieCollection]::new()
        $COLLECT.Add($COOKIE1)
        $COLLECT.Add($COOKIE2)
        $LOGIN.CookieCollection.ForEach({ $COLLECT.Add($_) })
    
        $SESSION = Execute-WebRequest -Method POST `
             -ENCRYPTEDBODY $BODY `
             -Headers $WebHeaderCollection[2] `
             -Uri "https://twitter.com/sessions" `
             -CONTENT_TYPE "application/x-www-form-urlencoded" `
             -DEFAULTCOOKIES $COLLECT
    
        $REDIRECT = Execute-WebRequest -Method GET `
             -Headers $WebHeaderCollection[3] `
             -DEFAULTCOOKIES $SESSION.CookieCollection `
             -Uri 'https://twitter.com'
    
        $USERNAME = CheckAuthGetUser -HTMLRESPONSETEXT $REDIRECT.ResponseText
    
        if(!$USERNAME){
            if(
                ([Microsoft.VisualBasic.Interaction]::MsgBox(
                        "Credentials were invalid!`nTry again?",
                        [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                        "Twitter Scraping Machine"
                    )) -eq "No"
            ){
                exit
            }
        }
    }
    #### LOGIN AUTH END ####
    Write-Host "############################################$(@((0..$USERNAME.length).forEach({ "#" })) -join '')" -ForegroundColor White;
    Write-Host "# " -NoNewline -ForegroundColor White
    Write-Host "Login Succeeded! Your Twitter handle is: " -ForegroundColor Yellow -NoNewline
    Write-Host "$($USERNAME)" -ForegroundColor Green -NoNewline
    Write-Host " #" -ForegroundColor White
    Write-Host "############################################$(@((0..$USERNAME.length).forEach({ "#" })) -join '')" -ForegroundColor White;
    
    $CSRF = [System.Convert]::ToBase64String(
        [System.Security.Cryptography.ProtectedData]::Protect(
            [System.Text.Encoding]::Unicode.GetBytes(
                @($REDIRECT.CookieCollection).Where({ $_.Name.Contains("ct0") }).Value
            ),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )
    
    $GLOBAL:TWPARAMS = @{
        BEARER=$BEARER_TOKEN;
        COOKIES=$REDIRECT.CookieCollection;
        CSRF=$CSRF;
        HEADERS=$h;
    }

    write-host "To execute authenticated " -foreGroundColor White -NoNewLine
    write-host "HTTP GET " -ForeGroundColor GREEN -NoNewLine
    write-host "requests against the " -foreGroundColor White -NoNewLine
    write-host "api.twitter.com/2 " -foreGroundColor Green -NoNewLine
    write-host "endpoint" -foreGroundColor White
    write-host "`n"
    write-host "You can use: " -ForegroundColor White 
    write-host "`tExecute-TwitterRequest" -foreGroundColor Yellow -NoNewLine
    write-host " -Uri " -ForeGroundColor Blue -NoNewLine 
    write-host "`"https://api.twitter.com/2/...`"`n" -foregroundColor Green
    write-host "in this PowerShell session." -ForeGroundColor White
}
function Get-EpochUnixTimeUTC
{
    [CmdletBinding()]
    param()
    return [math]::Round((([datetime]::UtcNow - [datetime]"01-01-1970") | % totalseconds))
}
function TW-TargetPage
{
    return [Dialog.Prompt]::ShowDialog("Enter the Twitter url to the page that you're scraping." + [System.Environment]::NewLine + "It should be formatted like: " + [System.Environment]::NewLine + "    https://twitter.com/screen_name/path","Twitter Scraping Machine","https://twitter.com/")
}
function CreateDownload-Folders
{
    param(
        [string]$LINK
    )
    $ROOTF = "$($ENV:TWDOWNLOAD)\$([dateTime]::Now.ToString('u').split(' ')[0])\$($LINK.split('/')[3])"
    @(
        $ROOTF,
        "$($ROOTF)\VID\",
        "$($ROOTF)\IMG\",
        "$($ROOTF)\VID\ENCODED\"
    ).ForEach({
        if(![System.IO.Directory]::Exists("$($_)")){
            $null = [System.IO.Directory]::CreateDirectory("$($_)")
            Write-Host "Created directory: " -ForegroundColor yellow -NoNewline
            Write-Host "$($_)" -ForegroundColor Green
        } else {
            Write-Host "Directory already exists: " -ForegroundColor Yellow -NoNewline
            Write-Host "$($_)" -ForegroundColor Green
        }
    })
    return $ROOTF
}

function Detect-Redirect
{
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$URI
    )
    $REG = [System.Text.RegularExpressions.Regex]::new("https://twitter.com/(.+)/status/(\d+)/(.+)")
    Remove-Variable n,r,rd -ea 0
    $rd = $false
    $n = $URI -replace "\)$",''
    @(
        "https://t.co",
        "http://t.co",
        "http://twitgoo.com",
        "tumblr.com",
        "https://vine.co"
    ).ForEach({ if($_ -match $n){ $rd = $true; continue; } })
    if($rd){
        try {
            $r = Execute-WebRequest -Method HEAD -Uri $n -NO_COOKIE
        }
        catch {
            $e = $_
            "HTTP HEAD request failed for $($n)" | Out-File $EXCEPTIONLOG -Encoding ascii -Append
            $e.Exception | % { $_ | Out-File $EXCEPTIONLOG -Encoding ascii -Append }
        }
        if($r){
            $redi = $r.HttpResponseMessage.Result.RequestMessage.RequestUri.AbsoluteUri
            if($redi -ne $n){
                if(
                    !$REG.Match($redi).Success -and `
                    $GLOBAL:LINKS.IndexOf($redi) -eq -1 -and `
                    $redi -notmatch 'video_thumb' -and `
                    $redi -match 'twimg' -or `
                    $redi -match 'twitpic'
                ){
                    return $redi
                }
            } else {
                if(
                    !$REG.Match($n).Success -and `
                    $GLOBAL:LINKS.IndexOf($n) -eq -1 -and `
                    $n -notmatch 'video_thumb' -and `
                    $n -match 'twimg' -or `
                    $n -match 'twitpic'
                ){
                    return $n
                }
            }
        }
    } else {
        if(
            !$REG.Match($n).Success -and `
            $GLOBAL:LINKS.IndexOf($n) -eq -1 -and `
            $n -notmatch 'video_thumb' -and `
            $n -match 'twimg' -or `
            $n -match 'twitpic'
        ){
            return $n
        } else {
            $n | out-file "$($ENV:TWDOWNLOAD)\TWExternalLinks.txt" -encoding ascii -Append
        }
    }
}
function Get-TwMediaUris
{
    param(
        $TWEETOBJECT
    )
    $MLINKS = @()
    @(
        "$($TWEETOBJECT | % extended_entities | % media | % video_info | % variants | sort bitrate -Descending | select -First 1 | % url)",
        "$($TWEETOBJECT | % extended_entities | % media | % media_url_https)",
        "$($TWEETOBJECT | % entities | % media | % media_url_https)",
        "$($TWEETOBJECT | % track | % playbackurl)",
        "$($TWEETOBJECT | % entities | % urls | % expanded_url)",
        @("$($TWEETOBJECT | % full_text)".split(' ')).Where({ $_.Contains("http") })
    ).Where({$_}).ForEach({$MLINKS+= $_})
    if($MLINKS){
        @($MLINKS).Where({$_ -match "mp4"})
        if($MLINKS.Count -eq 1){
            $CURRENT = $MLINKS[0]
            $SINGLE = @($MLINKS[0].Split("`n")).Where({$_.Contains("http")}) | Detect-Redirect
            if(
                !$SINGLE -and `
                $GLOBAL:LINKS.IndexOf($SINGLE) -ne -1
            ){ } else {
                $GLOBAL:LINKS += $SINGLE
            }
        } else {
            $MLINKS.forEach({
                remove-Variable current,uri,u,b4 -ea 0
                $current = $_
                if($current -match "\s"){
                    $u = @()
                    @($current.split(" ")).ForEach({ $u += $_ })
                }
                if($current -match "`n"){
                    $u = @()
                    @($current.split("`n")).ForEach({ $u += $_ })
                }
                if($u){
                    if($u.Count -gt 1){
                        $u.forEach({
                            $URI = $_ | Detect-Redirect
                            if(
                                !$URI -and `
                                $GLOBAL:LINKS.IndexOf($_) -ne -1
                            ){ } else {
                                $GLOBAL:LINKS += $URI
                            }
                        })
                    }
                    if($u.Count -eq 1){
                        $URI = $u | Detect-Redirect
                        if(
                            !$URI -and `
                            $GLOBAL:LINKS.IndexOf($_) -ne -1
                        ){ } else {
                            $GLOBAL:LINKS += $URI
                        }
                    }
                } else {
                    $URI = $current | Detect-Redirect
                    if(
                        !$URI -and `
                        $GLOBAL:LINKS.IndexOf($_) -ne -1
                    ){ } else {
                        $GLOBAL:LINKS += $URI
                    }
                }
            })
        }
        return $true
    } else {
        return $false
    }
}
function Download-Image
{
    param(
        [string]$MEDIAURL,
        [string]$TWROOT,
        [string]$LINK,
        [string]$BEARER_TOKEN,
        [string]$CSRF
    )
    $BEARER_TOKEN = [System.Text.Encoding]::Unicode.GetString(
        [System.Security.Cryptography.ProtectedData]::Unprotect(
            [System.Convert]::FromBase64String($BEARER_TOKEN),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )
    $CSRF = [System.Text.Encoding]::Unicode.GetString(
        [System.Security.Cryptography.ProtectedData]::Unprotect(
            [System.Convert]::FromBase64String($CSRF),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )
    Write-Host "Image found: " -ForegroundColor Red -NoNewline
    Write-Host "$($MEDIAURL)" -ForegroundColor Green
    if($MEDIAURL.StartsWith("data")){
        $OUTFILE = "$($TWROOT)\IMG\$($LINK.Split('/')[-1])_.$(@($LINK.Split('/')[1]).Split(';')[0])"
        $BYTES = @(); $BYTES += [System.Convert]::FromBase64String("$($MEDIAURL.Split(',')[-1])")
        [System.IO.File]::WriteAllBytes($OUTFILE,$BYTES)
    }
    if($MEDIAURL.Contains("twimg")){
        $OUTFILE = "$($TWROOT)\IMG\$($MEDIAURL.Split('/')[-1])"
        $WEBCLIENT = [System.Net.WebClient]::new()
        $H = [System.Net.WebHeaderCollection]::new()
        $H.Add("x-csrf-token","$($CSRF)")
        $H.Add("authority","api.twitter.com")
        $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
        $H.Add("authorization","Bearer $($BEARER_TOKEN)")
        $WEBCLIENT.Headers = $H
        $WEBCLIENT.Proxy = $null
        try {
            $WEBCLIENT.DownloadFile($MEDIAURL,$OUTFILE)
        }
        catch {
            $e = $
            $MEDIAURL | Out-File $EXCEPTIONLOG -Encoding ascii -Append
            $e.Exception | % { $_ | Out-File $EXCEPTIONLOG -Encoding ascii -Append }
        }
    }
    if($MEDIAURL.Contains("twitpic")){
        $R = Execute-WebRequest -Method GET `
             -Uri "$($MEDIAURL)" `
             -NO_COOKIE
        $URI = $R.HtmlDocument.body.getElementsByTagName("img")[0].src
        $S = Execute-WebRequest -Method GET `
             -Uri $URI `
             -NO_COOKIE
        $IMG = $S.HttpResponseMessage.Result.Content.ReadAsByteArrayAsync()
        $FILE = "$($TWROOT)\IMG\$("$(@($URI.Split('/')).Where({$_.Contains(".jpg")}))".Split('?')[0])"
        [System.IO.File]::WriteAllBytes($FILE,$IMG.Result)
    }
}
function Download-Video
{
    param(
        [string]$VIDEOURL,
        [string]$CSRF,
        [string]$TWROOT,
        [string]$BEARER_TOKEN
    )
    $CSRF = [System.Text.Encoding]::Unicode.GetString(
        [System.Security.Cryptography.ProtectedData]::Unprotect(
            [System.Convert]::FromBase64String($CSRF),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )
    $BEARER_TOKEN = [System.Text.Encoding]::Unicode.GetString(
        [System.Security.Cryptography.ProtectedData]::Unprotect(
            [System.Convert]::FromBase64String($BEARER_TOKEN),
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
    )
    Write-Host "Video found: " -ForegroundColor Red -NoNewline
    Write-Host "$($VIDEOURL)" -ForegroundColor Green
    if($VIDEOURL.Contains("mp4")){
        $WEBCLIENT = [System.Net.WebClient]::new()
        $H = [System.Net.WebHeaderCollection]::new()
        $H.Add("x-csrf-token","$($CSRF)")
        $H.Add("authority","api.twitter.com")
        $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
        $H.Add("authorization","Bearer $($BEARER_TOKEN)")
        $WEBCLIENT.Headers = $H
        $FILE = "$($TWROOT)\VID\$(($videoUrl.Split('/')[-1]).split('?')[0])"
        $ENCODED = "$($TWROOT)\VID\ENCODED\$(($VIDEOURL.Split('/')[-1]).split('?')[0])"
        $WEBCLIENT.Proxy = $null
        try {
            $WEBCLIENT.DownloadFile($VIDEOURL,$FILE)
        }
        catch [System.Net.WebException]{
            $e = $_
            $VIDEOURL | Out-File $EXCEPTIONLOG -Encoding ascii -Append
            $e.Exception | % { $_ | Out-File $EXCEPTIONLOG -Encoding ascii -Append }
        }
        if(!$NOFFMPEG -and !$DONT_REENCODE_VIDEOS){
            $JOB = [System.Diagnostics.Process]::new()
            $SI = [System.Diagnostics.ProcessStartInfo]::new()
            $SI.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized
            $SI.FileName = "C:\Windows\system32\cmd.exe"
            $SI.Arguments = " /c `"ffmpeg.exe -i `"$($FILE)`" `"$($ENCODED)`" -hide_banner`""
            $JOB.StartInfo = $si
            $null = $JOB.start()
        }
    }
    if($VIDEOURL.Contains("m3u")){
        $WEBCLIENT = [System.Net.WebClient]::new()
        $H = [System.Net.WebHeaderCollection]::new()
        $H.Add("x-csrf-token","$($CSRF)")
        $H.Add("authority","api.twitter.com")
        $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
        $H.Add("authorization","Bearer $($BEARER_TOKEN)")
        $WEBCLIENT.Headers = $H
        $M3U = $WEBCLIENT.DownloadString($videoUrl)
        $WEBCLIENT.dispose(); Remove-Variable WEBCLIENT -ea 0
        $WEBCLIENT = [System.Net.WebClient]::new()
        $H = [System.Net.WebHeaderCollection]::new()
        $H.Add("x-csrf-token","$($CSRF)")
        $H.Add("authority","api.twitter.com")
        $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
        $H.Add("authorization","Bearer $($BEARER_TOKEN)")
        $WEBCLIENT.Headers = $H
        $M3U8 = $WEBCLIENT.DownloadString(
            "https://video.twimg.com$($M3U.split("`n").where({
                    $_ -match "$(($M3U.split("`n").where({$_ -match 'RESOLUTION'}).forEach({
                        @{"$(($_.split('=')[2]).split(',')[0])"= ([int]("$(($_.split('=')[2]).split(',')[0])".split('x')[0]) * [int]("$(($_.split('=')[2]).split(',')[0])".split('x')[1]));}
                    })) | sort values -Descending | select -First 1 | % keys)"
                }) | select -last 1)"
        )
        $VIDBYTES = @();
        $M3U8.split("`n").Where({ $_ -match "\.ts$" }).ForEach({
                $URL = "https://video.twimg.com$($_)"
                $WEBCLIENT = [System.Net.WebClient]::new()
                $H = [System.Net.WebHeaderCollection]::new()
                $H.Add("x-csrf-token","$($CSRF)")
                $H.Add("authority","api.twitter.com")
                $H.Add("accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
                $H.Add("authorization","Bearer $($BEARER_TOKEN)")
                $WEBCLIENT.Headers = $H
                $WEBCLIENT.Proxy = $null
                $VIDBYTES += $WEBCLIENT.DownloadData($URL)
                $WEBCLIENT.dispose(); Remove-Variable wc,url -ea 0
            })
        $FILE = "$($TWROOT)\VID\$(($VIDEOURL.Split('/')[-1]).split('?')[0])" -replace "\.m3u8$",".mp4"
        [System.IO.File]::WriteAllBytes($file,$VIDBYTES)
        if(!$DONT_REENCODE_VIDEOS){
            $ENCODED = "$($TWROOT)\VID\ENCODED\$(($VIDEOURL.Split('/')[-1]).split('?')[0])" -replace "\.m3u8",".mp4"
            $JOB = [System.Diagnostics.Process]::new()
            $SI = [System.Diagnostics.ProcessStartInfo]::new()
            $SI.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Minimized
            $SI.FileName = "C:\Windows\system32\cmd.exe"
            $SI.Arguments = " /c `"ffmpeg.exe -i `"$($FILE)`" `"$($ENCODED)`" -hide_banner`""
            $JOB.StartInfo = $SI
            $null = $JOB.start()
        }
    }
}
Function Execute-TwitterRequest
{
    [cmdletbinding()]
    Param(
        [string]$URI
    )
    $BEARER_TOKEN = $GLOBAL:TWPARAMS.BEARER
    $CSRF = $GLOBAL:TWPARAMS.CSRF
    $HEADERS = $GLOBAL:TWPARAMS.HEADERS
    $COOKIES = $GLOBAL:TWPARAMS.COOKIES
    $HEADERS.Remove("path"); $HEADERS.Add("path","/$($URI.Split('/')[3..(@($URI.Split('/')).Length)] -join '/')")
    $TWRES = Execute-WebRequest -METHOD GET `
    -BEARER $BEARER_TOKEN `
    -CSRF $CSRF `
    -HEADERS $HEADERS `
    -DEFAULTCOOKIES $COOKIES `
    -NO_COOKIE `
    -URI $URI
    return $TWRES
}
Function Scrape-Page
{
    [cmdletbinding()]
    Param(
        [string]$TARGET_URI
    )
    Check-Env -TARGET_URI $TARGET_URI
    if(!$GLOBAL:TWPARAMS){
        Twitter-Login
    }
    $BEARER_TOKEN = $GLOBAL:TWPARAMS.BEARER
    $CSRF = $GLOBAL:TWPARAMS.CSRF
    if(!$TARGET_URI){
        $TARGET_URI = TW-TargetPage
    }
    if(
        $TARGET_URI -match "^twitter.com" -or `
        $TARGET_URI -match "^mobile.twitter.com"
    ){
        $TARGET_URI = "https://$($TARGET_URI)"
    }
    $MALFORMED = $false
    try {
        $SCRAPEURI = [uri]::new($TARGET_URI)
    }
    catch {
        $SCRAPEURI = $false
        $MALFORMED = $true
    }
    if($SCRAPEURI){
        if(
            $SCRAPEURI.scheme -ne 'https' -or `
            $SCRAPEURI.authority -notmatch 'twitter.com' -or `
            $SCRAPEURI.Segments.length -lt 2
    
        ){
            $MALFORMED = $true
        }
    }
    While($MALFORMED){
        $null = [Microsoft.VisualBasic.Interaction]::MsgBox(
            "The url $($TARGET_URI) is not correctly formatted.`nPlease format the url like: https://twitter.com/screen_name/path",
            [Microsoft.VisualBasic.MsgBoxStyle]::Critical,
            "Twitter Scraping Machine"
        )
        $TARGET_URI = TW-TargetPage
        if(
            $TARGET_URI -match "^twitter.com" -or `
            $TARGET_URI -match "^mobile.twitter.com"
        ){ $TARGET_URI = "https://$($TARGET_URI)" }
        $SCRAPEURI = $false
        try {
            $SCRAPEURI = [uri]::new($TARGET_URI)
        }
        catch {
            $SCRAPEURI = $false
            $MALFORMED = $true
        }
        if($SCRAPEURI){
            if(
                $SCRAPEURI.scheme -eq 'https' -and `
                $SCRAPEURI.authority -match 'twitter.com' -or `
                $SCRAPEURI.Segments.length -ge 2
            ){
                $MALFORMED = $false
            }
        }
    }
    $TARGET_URI = $TARGET_URI -replace "/$",''
    $SCRAPEURI = [uri]::new($TARGET_URI)
    $HANDLE = $SCRAPEURI.Segments[1] -replace "/",''
    
    $USER = Execute-WebRequest -Method GET `
         -NO_COOKIE `
         -BEARER $BEARER_TOKEN `
         -Uri "https://api.twitter.com/1.1/users/show.json?screen_name=$($HANDLE)"
    
    $uJSON = $USER.ResponseText | ConvertFrom-Json
    $rTWID = $uJSON | % id
    $epochtime = Get-EpochUnixTimeUTC
    $EXCEPTIONLOG = "$($ENV:TWDOWNLOAD)\Exceptions_$($EpochTime).txt"
    $DLLINKLOG = "$($ENV:TWDOWNLOAD)\Download_Links_$($EpochTime).txt"
    if($TARGET_URI.Contains("likes")){
        $MEDIA_COUNT = $uJSON | % favourites_count
        $URI = "https://api.twitter.com/2/timeline/favorites/$($rTWID).json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&count=$($MEDIA_COUNT)&ext=mediaStats%2CcameraMoment"
    }
    if($TARGET_URI.Contains("media")){
        $MEDIA_COUNT = $uJSON | % media_count
        $URI = "https://api.twitter.com/2/timeline/media/$($rTWID).json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&count=$($MEDIA_COUNT)&ext=mediaStats%2CcameraMoment"
    }
    if(@($TARGET_URI.split('/')).length -eq 4){
        $MEDIA_COUNT = $uJSON | % statuses_count
        $URI = "https://api.twitter.com/2/timeline/profile/$($rTWID).json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&count=$($MEDIA_COUNT)&ext=mediaStats%2CcameraMoment"
    }
    $TWEETS = Execute-TwitterRequest -URI $URI
    $TWROOT = CreateDownload-Folders -LINK $TARGET_URI
    Remove-Variable -Scope Global -Name LINKS -ea 0
    $GLOBAL:LINKS = @()
    $FINDMEDIA = @()
    $JSON = $TWEETS.ResponseText | ConvertFrom-Json
    $TWTS = $JSON | % globalObjects | % tweets
    $TWTSALL = @($JSON | % globalObjects | % tweets | gm -MemberType NoteProperty).Length
    $TWTSC = 0
    $ex = @()
    $bwstart = [Console]::BufferWidth
    [console]::bufferWidth = [Console]::WindowWidth
    $TWTS | gm -MemberType NoteProperty | % Name | % {
        $TWTSC++
        Remove-Variable TID,TWEETOBJECT -ea 0
        $TID = $_
        $TWEETOBJECT = $TWTS | % $TID
        if(!(Get-TwMediaUris -TWEETOBJECT $TWEETOBJECT)){
            $FINDMEDIA += $TWEETOBJECT
        }
        Write-Progress -PercentComplete ($TWTSC/$TWTSALL*100) -Status "$([math]::Round(($TWTSC/$TWTSALL*100),2))%" -Activity "$($GLOBAL:LINKS.Count) links parsed :: $($TWTSC) of $($TWTSALL) tweets checked"
    }
    $START = Get-Date
    $COUNT = 0
    $ALL = $GLOBAL:LINKS.Count
    $VIDCOUNT = 0
    $IMGCOUNT = 0
    $GLOBAL:LINKS.ForEach({
        $COUNT++
        $uri = $_
        $pre = $_.split('/')[0..2] -join '/'
        try {
            switch ($pre){
                "https://pbs.twimg.com" { Download-Image -MEDIAURL $uri -TWROOT $TWROOT -BEARER_TOKEN $BEARER_TOKEN -CSRF $CSRF; $ImgCount++ }
                "https://video.twimg.com" { Download-Video -VIDEOURL $uri -CSRF $CSRF -TWROOT $TWROOT -BEARER_TOKEN $BEARER_TOKEN; $vidCount++ }
                "http://twitpic.com" { Download-Image -MEDIAURL $uri -TWROOT $TWROOT -BEARER_TOKEN $BEARER_TOKEN -CSRF $CSRF; $ImgCount++ }
            }
        }
        catch {
            $e = $_
            $e.Exception | % { $_ | Out-File $EXCEPTIONLOG -Encoding ascii -Append }
        }
        $now = [datetime]::Now
        $elapse = ($now - $START) |% totalSeconds
        $remain = ($elapse * ($ALL / $COUNT)) - $elapse
        ($now.AddSeconds($remain) - $now) | select days,hours,minutes,seconds,milliseconds |% {
            $d = $_ |% days
            $h = $_ |% hours
            $m = $_ |% minutes
            $s = $_ |% seconds
            $ms = $_ |% milliseconds
        }
        $STRING = "$($d) days :: $($h) hours :: $($m) minutes :: $($s) seconds ::$($ms) remaining"
        $HOST.ui.RawUI.WindowTitle = "$($STRING) :: $([math]::Round(($COUNT/$ALL*100),2))% :: $($COUNT) of $($ALL)";
        Write-Progress -PercentComplete ($COUNT / $ALL * 100) -Status "$($STRING) :: $([math]::Round(($COUNT/$ALL*100),2))%" -Activity "$($COUNT) of $($ALL) :: Videos: $($vidCount) :: Images: $($ImgCount)"
    })
    [Console]::BufferWidth = $bwstart
}
