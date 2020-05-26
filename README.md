     _______       _ _   _             __          __  _        _____                                  
    |__   __|     (_) | | |            \ \        / / | |      / ____|                                 
       | |_      ___| |_| |_ ___ _ __   \ \  /\  / /__| |__   | (___   ___ _ __ __ _ _ __   ___ _ __   
       | \ \ /\ / / | __| __/ _ \ '__|   \ \/  \/ / _ \ '_ \   \___ \ / __| '__/ _' | '_ \ / _ \ '__|  
       | |\ V  V /| | |_| ||  __/ |       \  /\  /  __/ |_) |  ____) | (__| | | (_| | |_) |  __/ |     
       |_| \_/\_/ |_|\__|\__\___|_|        \/  \/ \___|_.__/  |_____/ \___|_|  \__,_| .__/ \___|_|     
                                                                                    | |                
                                                                                    |_|                
  

[Click here to view this page in HTML instead of markdown](https://nanick.hopto.org/twreadme.html)
## Under Construction Again! Some of the instruction below may not reflect how this solution is intended to be used!
## Requirements

*   **Microsoft Windows** operating system

        (tested on **Windows 10** Version 1909 OS build 18363.720 and **Windows Server 2016** Version 1607 OS build 14393.3564)

*   **Windows PowerShell**, minimum version 3.0

        (tested PowerShell versions **3.0**, **5.1.14393.3471**, and **5.1.18362.628**. I have not tested PowerShell Core.)

*   A Twitter account (**username** and **password**)

*   A Twitter page that you would like to srape the media off of

## Installation  

*   **Launch PowerShell and run the code below:**  
```ps1
mkdir C:\TEMP\BIN -ea 0
cd C:\TEMP\BIN 
git clone https://github.com/nstevens1040/PowerShell-Twitter-web-scraper.git 
cd PowerShell-Twitter-web-scraper 
. .\PSTwitter-Media-Scraper.ps1
```  
*   **You can also launch PowerShell and run:**  
```ps1
iex (irm "https://raw.githubusercontent.com/nstevens1040/PSTwitter-Media-Scraper/master/PSTwitter-Media-Scraper.ps1")
```  
Either one will make the function **Scrape-TWPage** available in your current PowerShell session.  
## Environment Variables  
   The first time you run **Scrape-TWPage** you will be asked to set two environment variables:  
1.  **TWDOWNLOAD** : Points to a root folder to store all of your download images and videos.  
  
![ScreenShot](https://github.com/nstevens1040/PSTwitter-Media-Scraper/raw/master/.gitignore/Capture1.PNG)  
  
2.  **EXWEBREQ** : Points to a root folder to store any .NET assemblies necessary to use [Execute-WebRequest](https://github.com/nstevens1040/Execute-WebRequest).  
  
![ScreenShot](https://github.com/nstevens1040/PSTwitter-Media-Scraper/raw/master/.gitignore/Capture2.PNG)  
  
## Usage  

1.  **Scrape-TWPage** takes one argument called **-TARGET_URI**. This is the Uri that takes you to the Twitter page that you would like to scrape the media off of.  

    **SYNTAX:**  
    ``Scrape-TWPage [[-TARGET_URI] &lt;string&gt;]  [&lt;CommonParameters&gt;]``  

2.  A Windows credential dialog appears, asking you to enter the **username** and **password** that you use to login to Twitter.  

    **Your username, password, bearer tokens, and csrf tokens are protected with the [System.Security.Cryptography.ProtectedData](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata?view=netframework-4.8) .NET Framework class which provides access to Microsoft's Data Protection API.**

At this point, you are finished entering the information necessary to proceed. The script's output will keep you updated on it's progress.

The steps above are illustrated in the video below.
![ScreenShot](https://github.com/nstevens1040/PSTwitter-Media-Scraper/raw/master/.gitignore/PSTwitterScraperUsage.gif)

