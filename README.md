<pre style="font-weight: bold;background-color: black; color:yellow;"> _______       _ _   _             __          __  _        _____                                
|__   __|     (_) | | |            \ \        / / | |      / ____|                               
   | |_      ___| |_| |_ ___ _ __   \ \  /\  / /__| |__   | (___   ___ _ __ __ _ _ __   ___ _ __ 
   | \ \ /\ / / | __| __/ _ \ '__|   \ \/  \/ / _ \ '_ \   \___ \ / __| '__/ _` | '_ \ / _ \ '__|
   | |\ V  V /| | |_| ||  __/ |       \  /\  /  __/ |_) |  ____) | (__| | | (_| | |_) |  __/ |   
   |_| \_/\_/ |_|\__|\__\___|_|        \/  \/ \___|_.__/  |_____/ \___|_|  \__,_| .__/ \___|_|   
                                                                                | |              
                                                                                |_|                 
        </pre>

[Click here to view this page in HTML instead of markdown](https://nanick.hopto.org/twreadme.html)

## Requirements

*   **Microsoft Windows** operating system

        (tested on **Windows 10** Version 1909 OS build 18363.720 and **Windows Server 2016** Version 1607 OS build 14393.3564)

*   **Windows PowerShell**, minimum version 3.0

        (tested PowerShell versions **3.0**, **5.1.14393.3471**, and **5.1.18362.628**. I have not tested PowerShell Core.)

*   A Twitter account (**username** and **password**)

*   A Twitter page that you would like to srape the media off of

## Usage

1.  Launch PowerShell as administrator and run the code below:

    <pre><code>mkdir C:\TEMP\BIN
    cd C:\TEMP\BIN 
    git clone https://github.com/nstevens1040/PowerShell-Twitter-web-scraper.git 
    cd PowerShell-Twitter-web-scraper 
    .\Create-DesktopShortcut.ps1 
    exit</code></pre>
2.  There should now be a shortcut named **Twitter Media Scraper** on your desktop. Double click the shortcut.

3.  You will be asked if you have a secondary bearer token to use just in case you hit a rate limit.  
    If you do not have another bearer token, then click **No**.  
    If you do, then click **Yes** and enter your secondary bearer token.

4.  An input box appears. Enter the **full URL to the Twitter page** that you want to scrape all the media off of.

5.  A Windows credential dialog appears, asking you to enter the **username** and **password** that you use to login to Twitter.  

    **Your username, password, bearer tokens, and csrf tokens are protected with the [System.Security.Cryptography.ProtectedData](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata?view=netframework-4.8) .NET Framework class which provides access to Microsoft's Data Protection API.**

At this point, you are finished entering the information necessary to proceed. The script's output will keep you updated on it's progress.

The steps above are illustrated in the video below.
![ScreenShot](https://github.com/nstevens1040/PSTwitter-Media-Scraper/raw/master/.gitignore/PSTwitterGif_part_one.gif)

