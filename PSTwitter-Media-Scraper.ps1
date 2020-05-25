Function Scrape-TWPage
{
    [cmdletbinding()]
    Param(
        [string]$TARGET_URI
    )
    iex (irm "https://raw.githubusercontent.com/nstevens1040/Execute-WebRequest/master/INSTALL.ps1")
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
    function Detect-Redirect
    {
        [cmdletbinding()]
        Param(
            [Parameter(ValueFromPipeline=$true)]
            [string]$URI
        )
        $ec = @($Error).Where({$_.Exception -notmatch "variable" -and $_.Exception -notmatch "The format of the URI"}).Count
        $REG = [System.Text.RegularExpressions.Regex]::new("https://twitter.com/(.+)/status/(\d+)/(.+)")
        Remove-Variable n,r,rd,u -ea 0
        $rd = $false
        $n = $URI -replace "\)",'' -replace "\*","\*"
        try {
            $u = [uri]::New($n)
        }
        catch { }
        if($u){
            @(
                "https://t.co",
                "http://t.co",
                "http://twitgoo.com",
                "tumblr.com",
                "https://vine.co"
            ).ForEach({ if($_ -match $n){ $rd = $true } })
            if($rd){
                try {
                    $r = Execute-WebRequest -Method HEAD -Uri $n -NO_COOKIE -SILENT
                }
                catch {
                    $e = $_
                    Write-Host $n
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
                    $n | out-file "$([System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE"))\TWExternalLinks_$(Get-EpochUnixTimeUTC).txt" -encoding ascii -Append
                }
            }
            if($ec -lt @($Error).Where({$_.Exception -notmatch "variable" -and $_.Exception -notmatch "The format of the URI"}).Count){
                $diff = @($Error).Where({$_.Exception -notmatch "variable" -and $_.Exception -notmatch "The format of the URI"}).Count - $ec
                for($i = 0; $i -lt (@($Error).Where({$_.Exception -notmatch "variable" -and $_.Exception -notmatch "The format of the URI"}) | select -last $diff).Count; $i++){
                    $e = (@($Error).Where({$_.Exception -notmatch "variable" -and $_.Exception -notmatch "The format of the URI"}) | select -last $diff)[$i]
                    $e | select * | out-File $EXCEPTIONLOG -Append -Encoding ascii
                }
            }
        }
    }
    function Get-EpochUnixTimeUTC
    {
        [CmdletBinding()]
        param()
        return [math]::Round((([datetime]::UtcNow - [datetime]"01-01-1970") | % totalseconds))
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
    Function Twitter-Login
    {    
        [CmdletBinding()]
        param(
            #[switch]$DONT_REENCODE_VIDEOS = $true
        )
        #Start-IE
        #AddAllAssemblies
        #SetConsoleOptions
        if(!$BEARER_TOKEN){
            $BEARER_TOKEN = Get-TWBearerToken
        }
        #### LOGIN AUTH START ####
        While(!$USERNAME){
            $ECS = Get-EncryptedCredentialString
        
            $CK1 = '{ "Comment": "", "CommentUri": null, "HttpOnly": false, "Discard": false, "Domain": "twitter.com", "Expired": false, "Expires": "\/Date(-62135575200000)\/", "Name": "app_shell_visited", "Path": "/", "Port": "", "Secure": false, "TimeStamp": "\/Date(1578913791674)\/", "Value": "1", "Version": 0}'
            $CK2 = '{ "Comment": "", "CommentUri": null, "HttpOnly": false, "Discard": false, "Domain": ".twitter.com", "Expired": true, "Expires": "\/Date(1578913611000)\/", "Name": "fm", "Path": "/", "Port": "", "Secure": false, "TimeStamp": "\/Date(1578913791689)\/", "Value": "0", "Version": 0}'
        
            $LOGIN = Execute-WebRequest -METHOD GET -URI "https://twitter.com/login"
            $FORMS = @(); @($LOGIN.HtmlDocument.getElementsByTagName("FORM")).ForEach({ $FORMS += $_ })
            $UIMET = Execute-WebRequest -Method GET -Uri "https://twitter.com/i/js_inst?c_name=ui_metrics"
            $EXPIRES = [DateTime]"$("$(@($UIMET.HttpResponseHeaders.Where({$_.Key -eq "Set-Cookie"})[0].Value.Split(';')).Where({$_ -match 'expires'}) | select -First 1)".Split('=')[1])"
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
        write-host "in this PowerShell session.`n" -ForeGroundColor White
    }
    function TW-TargetPage
    {
        return [Dialog.Prompt]::ShowDialog("Enter the Twitter url to the page that you're scraping." + [System.Environment]::NewLine + "It should be formatted like: " + [System.Environment]::NewLine + "    https://twitter.com/screen_name/path","Twitter Scraping Machine","https://twitter.com/")
    }
    Function Handle-MalFormedUri
    {
        [cmdletbinding()]
        Param(
            [string]$TARGET_URI
        )
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
        return $TARGET_URI
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
            $FILE = "$([System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE"))\VID\$(($videoUrl.Split('/')[-1]).split('?')[0])"
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
    function CreateDownload-Folders
    {
        param(
            [string]$LINK
        )
        $ROOTF = "$([System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE"))\$([dateTime]::Now.ToString('u').split(' ')[0])\$($LINK.split('/')[3])"
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
    if([System.IO.DirectoryInfo]::New("$($PWD.Path)").Name -eq 'PSTwitter-Media-Scraper'){ 
        $TWDOWNLOAD = "$($PWD.Path)"
    } else {
        $TWDOWNLOAD = "C:\TEMP\BIN\PSTwitter-Media-Scraper"
    }
    if([System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE")){ } else {
        Switch(
            [microsoft.visualbasic.Interaction]::MsgBox(
                "Now we'll need to set a download folder.`n`nClick 'Yes' to set environment variable:`n`n`t%TWDOWNLOAD%`nto:`n`t'$($TWDOWNLOAD)'`n`nClick 'No' to set a different download folder.",
                [Microsoft.VisualBasic.MsgBoxStyle]::YesNo,
                "TWITTER MEDIA SCRAPER"
            )
        ){
            "Yes" {
                if(![System.IO.Directory]::Exists($TWDOWNLOAD)){
                    $null = [System.IO.Directory]::CreateDirectory($TWDOWNLOAD)
                }
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
    if(!("System.Security.Cryptography.ProtectedData" -as [type])){
        $DLL = Load-MissingAssembly -AssemblyName "System.Security.Cryptography.ProtectedData"
        if($DLL){
            if($DLL.GetType() -eq [object[]]){ $DLL = $DLL[-1] }
            Add-Type -Path $DLL
            if($? -and [array]::IndexOf(@([System.IO.File]::ReadAllLines($PROFILE)),"Add-Type -Path `"$($DLL)`"") -eq -1){ "`nAdd-Type -Path `"$($DLL)`"" | Out-File $PROFILE -Encoding Ascii -Append }
            remove-variable DLL -ea 0
        }
    }
    $INPUTDIALOG_REFS = @(
        "C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Windows.Forms\v4.0_4.0.0.0__b77a5c561934e089\System.Windows.Forms.dll",
        "C:\WINDOWS\Microsoft.Net\assembly\GAC_MSIL\System.Drawing\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Drawing.dll",
        "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll"
    )
    $INPUTDIALOG = "using System.Windows.Forms;`r`nusing System.Drawing;`r`nusing System;`r`nnamespace Dialog`r`n{`r`n    public static class Prompt`r`n    {`r`n        public static string ShowDialog(string text, string caption, string phold = null)`r`n        {`r`n            int h = Convert.ToInt32(Math.Round(((Graphics.FromImage(new Bitmap(1,1))).MeasureString(text, new Font(`"Calibri`", 12)).Height)));`r`n            Form prompt = new Form()`r`n            {`r`n                Width = 500,`r`n                Height = 200,`r`n                FormBorderStyle = FormBorderStyle.FixedDialog,`r`n                Text = caption,`r`n                StartPosition = FormStartPosition.CenterScreen,`r`n                Font = new Font(`"Calibri`", 12)`r`n            };`r`n            Label textLabel = new Label(){ AutoSize = false, Height = h, Left = 50, Top=20, Width = 400, Text = text, Font = new Font(`"Calibri`", 12) };`r`n            TextBox textBox = new TextBox(){ Size = new Size(400,100), Left = 50, Top = (h + 30), Font = new Font(`"Calibri`", 12) };`r`n            if(phold != null)`r`n            {`r`n                textBox.Text = phold;`r`n            };`r`n            Button confirmation = new Button(){ Text = `"Ok`", Left = 350, Width = 100, Top = (h + 60), Font = new Font(`"Calibri`", 12), DialogResult = DialogResult.OK };`r`n            confirmation.Click += (sender, e) => { prompt.Close(); };`r`n            prompt.Controls.Add(textBox);`r`n            prompt.Controls.Add(confirmation);`r`n            prompt.Controls.Add(textLabel);`r`n            prompt.AcceptButton = confirmation;`r`n            return prompt.ShowDialog() == DialogResult.OK ? textBox.Text : `"`";`r`n        }`r`n    }`r`n}"
    $NATIVEM_WINDOWRECT = "using System;`nusing System.Runtime.InteropServices;`nnamespace NativeM`n{`n    public class Win32 {`n        [DllImport(`"user32.dll`")]`n        [return: MarshalAs(UnmanagedType.Bool)]`n        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);`n    `n        [DllImport(`"user32.dll`")]`n        [return: MarshalAs(UnmanagedType.Bool)]`n        public static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);`n    `n        [DllImport(`"user32.dll`")]`n        [return: MarshalAs(UnmanagedType.Bool)]`n        public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);`n    `n        [DllImport(`"user32.dll`")]`n        [return: MarshalAs(UnmanagedType.Bool)]`n        public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);`n    }`n    public struct RECT`n    {`n        public int Left;        // x position of upper-left corner`n        public int Top;         // y position of upper-left corner`n        public int Right;       // x position of lower-right corner`n        public int Bottom;      // y position of lower-right corner`n    }`n}"
    $CRED_DIALOG = "using System;`nusing System.Text;`nusing System.Runtime.InteropServices;`nusing System.Collections.Generic;`nnamespace WinCred`n{`n    public class CredentialDialog`n    {`n        [DllImport(`"ole32.dll`")]`n        public static extern void CoTaskMemFree(IntPtr ptr);`n        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]`n        public struct CREDUI_INFO`n        {`n            public int cbSize;`n            public IntPtr hwndParent;`n            public string pszMessageText;`n            public string pszCaptionText;`n            public IntPtr hbmBanner;`n        }`n        [DllImport(`"credui.dll`", CharSet = CharSet.Unicode)]`n        public static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,`n                                                             int authError,`n                                                             ref uint authPackage,`n                                                             IntPtr InAuthBuffer,`n                                                             uint InAuthBufferSize,`n                                                             out IntPtr refOutAuthBuffer,`n                                                             out uint refOutAuthBufferSize,`n                                                             ref bool fSave,`n                                                             int flags);`n        [DllImport(`"credui.dll`", CharSet = CharSet.Unicode)]`n        public static extern bool CredUnPackAuthenticationBuffer(int dwFlags,`n                                                           IntPtr pAuthBuffer,`n                                                           uint cbAuthBuffer,`n                                                           StringBuilder pszUserName,`n                                                           ref int pcchMaxUserName,`n                                                           StringBuilder pszDomainName,`n                                                           ref int pcchMaxDomainame,`n                                                           StringBuilder pszPassword,`n                                                           ref int pcchMaxPassword);`n        public static List<string> AuthEasy()`n        {`n            CREDUI_INFO credui = new CREDUI_INFO();`n            credui.pszCaptionText = `"Enter your network credentials`";`n            credui.pszMessageText = `"Enter your credentials to connect to: Twitter.com`";`n            credui.cbSize = Marshal.SizeOf(credui);`n            uint authPackage = 0;`n            IntPtr outCredBuffer = new IntPtr();`n            uint outCredSize;`n            bool save = false;`n`n            int result = CredUIPromptForWindowsCredentials(ref credui, 0, ref authPackage, IntPtr.Zero, 0, out outCredBuffer, out outCredSize, ref save, 1);`n`n            var usernameBuf = new StringBuilder(100);`n            var passwordBuf = new StringBuilder(100);`n            var domainBuf = new StringBuilder(100);`n`n            int maxUserName = 100;`n            int maxDomain = 100;`n            int maxPassword = 100;`n            List<string> clis = new List<string>();`n            if(result == 0)`n            {`n                if(CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, usernameBuf, ref maxUserName, domainBuf, ref maxDomain, passwordBuf, ref maxPassword))`n                {`n                    //clear the memory allocated by CredUIPromptForWindowsCredentials`n                    CoTaskMemFree(outCredBuffer);`n                    `n                    clis.Add(usernameBuf.ToString());`n                    clis.Add(passwordBuf.ToString());`n                    return clis;`n                } else`n                {`n                    return clis;`n                }`n            } else`n            {`n                return clis;`n            }`n        }`n    }`n}"
    if(!("Dialog.Prompt" -as [type])){
        Add-Type -TypeDefinition $INPUTDIALOG -ReferencedAssemblies $INPUTDIALOG_REFS
    }
    if(!("NativeM.Win32" -as [type])){
        Add-Type -TypeDefinition $NATIVEM_WINDOWRECT
    }
    if(!("WinCred.CredentialDialog" -as [type])){
        Add-Type -TypeDefinition $CRED_DIALOG
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
    if(!$GLOBAL:TWPARAMS){
        Twitter-Login
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
    $BEARER_TOKEN = $GLOBAL:TWPARAMS.BEARER
    $CSRF = $GLOBAL:TWPARAMS.CSRF
    if(!$TARGET_URI){
        $TARGET_URI = TW-TargetPage
    }
    $MALFORMED = Handle-MalFormedUri -TARGET_URI $TARGET_URI
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
    $EXCEPTIONLOG = "$([System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE"))\Exceptions_$($EpochTime).txt"
    $DLLINKLOG = "$([System.Environment]::GetEnvironmentVariable("TWDOWNLOAD","MACHINE"))\Download_Links_$($EpochTime).txt"
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
    $ex = @()
    $bwstart = [Console]::BufferWidth
    [console]::bufferWidth = [Console]::WindowWidth
    for($i = 0; $i -lt @($TWTS | gm -MemberType NoteProperty | % Name).Count; $i++){
        Remove-Variable TID,TWEETOBJECT -ea 0
        $TID = @($TWTS | gm -MemberType NoteProperty | % Name)[$i]
        $TWEETOBJECT = $TWTS | % $TID
        if(!(Get-TwMediaUris -TWEETOBJECT $TWEETOBJECT)){
            $FINDMEDIA += $TWEETOBJECT
        }
        Write-Progress -PercentComplete ($i/@($TWTS | gm -MemberType NoteProperty | % Name).Count*100) -Status "$([math]::Round(($i/@($TWTS | gm -MemberType NoteProperty | % Name).Count*100),2))%" -Activity "$($GLOBAL:LINKS.Count) links parsed :: $($i) of $(@($TWTS | gm -MemberType NoteProperty | % Name).Count) tweets checked"
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
