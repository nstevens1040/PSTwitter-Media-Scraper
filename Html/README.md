<html>

    <head>
        <meta charset="utf8">
        <style> 
        body { 
            margin-right: 500px;
            font-family: 'Lucida Sans', 'Lucida Sans Regular', 'Lucida Grande', 'Lucida Sans Unicode', Geneva, Verdana, sans-serif;
            font-size: 15px;
        } 
        h2 { 
            text-decoration: underline; font-size: 18px;
        } 
        /*pre { 
            background: #f4f4f4; 
            border: 1px solid #ddd; 
            border-left: 3px solid #f36d33; 
            color: #667; 
            page-break-inside: avoid; 
            font-family: monospace; 
            font-size: 15px; 
            line-height: 1.6; 
            margin-bottom: 10px; 
            overflow: auto; 
            padding: 10px 10px; 
            display: block; 
            word-wrap: break-word;
        }*/
        .fine { 
            color: #667; 
            font-style: italic; 
            font-size: 15px;
        }
        table {
            border: 1px solid black; 
        }
        tr,
        th,
        td {
            border-collapse: collapse;
            border: 1px solid black; 
            padding: 5px;
        }
        img {
            width: 800px;
        }
        textarea {
                    background: black;
                    border: 1px solid #ddd;
                    border-left: 3px solid #f36d33;
                    border-right: 1px solid #ddd;
                    color: white;
                    page-break-inside: avoid;
                    font-family: monospace;
                    font-size: 15px;
                    line-height: 1.6;
                    margin-bottom: 10px;
                    overflow: auto;
                    padding: 10px 10px;
                    display: block;
                    word-wrap: break-word;
        }
        </style>
        <script type="application/javascript">
            function copytext(id) {
                if (id == "vba") {
                    var t = document.getElementById("vba");
                    t.select();
                    document.execCommand("copy");
                    alert("You've copied the Excel VBA code to the clipboard!");
                }
                if (id == "m2") {
                    var t = document.getElementById("m2");
                    t.select();
                    document.execCommand("copy");
                    alert("You've copied method 2 to the clipboard!");
                }
                if (id == "ps1") {
                    var t = document.getElementById("ps1");
                    t.select();
                    document.execCommand("copy");
                    alert("Copied!");
                }
            }
        </script>
    </head>

<body>
        <pre style="font-weight: bold;background-color: black; color:yellow;">
 _______       _ _   _             __          __  _        _____                                
|__   __|     (_) | | |            \ \        / / | |      / ____|                               
   | |_      ___| |_| |_ ___ _ __   \ \  /\  / /__| |__   | (___   ___ _ __ __ _ _ __   ___ _ __ 
   | \ \ /\ / / | __| __/ _ \ '__|   \ \/  \/ / _ \ '_ \   \___ \ / __| '__/ _` | '_ \ / _ \ '__|
   | |\ V  V /| | |_| ||  __/ |       \  /\  /  __/ |_) |  ____) | (__| | | (_| | |_) |  __/ |   
   |_| \_/\_/ |_|\__|\__\___|_|        \/  \/ \___|_.__/  |_____/ \___|_|  \__,_| .__/ \___|_|   
                                                                                | |              
                                                                                |_|                 
        </pre>
    <h2>Requirements</h2>
    <ul>
        <li><p><b>Microsoft Windows</b> operating system </p><p class="fine">&nbsp;&nbsp;&nbsp;&nbsp;(tested on <b>Windows 10</b> Version 1909 OS build 18363.720 and <b>Windows Server 2016</b> Version 1607 OS build 14393.3564)</p></li>
        <li><p><b>Windows PowerShell</b>, minimum version 3.0 </p><p class="fine">&nbsp;&nbsp;&nbsp;&nbsp;(tested PowerShell versions <b>3.0</b>, <b>5.1.14393.3471</b>, and <b>5.1.18362.628</b>. I have not tested PowerShell Core.)</p></li>
        <li><p>A Twitter account (<b>username</b> and <b>password</b>)</p></li>
        <li><p>A Twitter page that you would like to srape the media off of</p></li>
    </ul>
    <h2>Usage</h2>
    <ol>
        <li><p> Launch PowerShell as administrator and run the code below:</p>
            <button style="display: inline;" onclick="copytext('ps1');"><b>Copy</b></button>
            <br/><textarea spellcheck="false" id="ps1" style="height: 170px; width: 800px">mkdir C:\TEMP\BIN
cd C:\TEMP\BIN
git clone https://github.com/nstevens1040/PowerShell-Twitter-web-scraper.git
cd PowerShell-Twitter-web-scraper
.\Create-DesktopShortcut.ps1
exit</textarea>
        </li>
        <li><p> There should now be a shortcut named <b>Twitter Media Scraper</b> on your desktop. Double click the shortcut.</p></li>
        <li><p> You will be asked if you have a secondary bearer token to use just in case you hit a rate limit. </br>If you do not have another bearer token, then click <b>No</b>. </br>If you do, then click <b>Yes</b> and enter your secondary bearer token.</p></li>
        <li><p> An input box appears. Enter the <b>full URL to the Twitter page</b> that you want to scrape all the media off of.</p></li>
        <li><p> A Windows credential dialog appears, asking you to enter the <b>username</b> and <b>password</b> that you use to login to Twitter. <br/></p>
            <b style="color: red;">Your username, password, bearer tokens, and csrf tokens are protected with the <a href="https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata?view=netframework-4.8" target="_blank">System.Security.Cryptography.ProtectedData</a> .NET Framework class which provides access to Microsoft's Data Protection API.</b>
        </li>
    </ol>
    <p>At this point, you are finished entering the information necessary to proceed. The script's output will keep you updated on it's progress.</p>
    <div>
        <p>The steps above are illustrated in the video below.</p>
        <video height="405" width="720" autoplay="" loop="" muted="" controls="" src="https://nanick.hopto.org/prod/PSTwitterVideo.mp4"></video>
    </div>
    <br>
    <br>
</body>
</html>
