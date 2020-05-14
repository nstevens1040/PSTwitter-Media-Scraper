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
                    Arguments = " -ep RemoteSigned -noprofile -nologo -c cd '$($PWD.Path)'; iex (irm 'https://raw.githubusercontent.com/nstevens1040/PSTwitter-Media-Scraper/master/INSTALL.ps1')"
                };
            }).Start()
            (Get-Process -Id $PID).kill()
        }
    }
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
                            Arguments = " -ep RemoteSigned -noprofile -nologo -c cd '$($CDIR)'; iex (irm 'https://raw.githubusercontent.com/nstevens1040/PSTwitter-Media-Scraper/master/INSTALL.ps1')"
                        };
                    }).Start()
                    (Get-Process -Id $PID).kill()
                }
            } else {
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
