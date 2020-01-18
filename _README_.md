# Requirements
1.  Windows OS ==> Internet Explorer and PowerShell
2.  Google Chrome
3.  FFMPEG
4.  A Twitter account (username and password)
5.  Twitter Bearer Token
6.  A list of links to individial tweets

##     Retrieving your Bearer Token
   1.  Launch Google Chrome
   2.  Hold CTRL+SHIFT and strike N to launch a new window in **Incognito Mode**.
   3.  Strike F12 to open developer tools and then click on the **Network** tab.
   4.  Back in your Incognito window, navigate to [https://twitter.com](https://twitter.com) and login.
   5.  Go back to the **Network** tab in developer tools and type **api.twitter.com/2** into the search field up top.
   6.  Find the request that starts with **home.json**. I left the full url below.  
```html
https://api.twitter.com/2/timeline/home.json?include_profile_interstitial_type=1&include_blocking=1&include_blocked_by=1&include_followed_by=1&include_want_retweets=1&include_mute_edge=1&include_can_dm=1&include_can_media_tag=1&skip_status=1&cards_platform=Web-12&include_cards=1&include_composer_source=true&include_ext_alt_text=true&include_reply_count=1&tweet_mode=extended&include_entities=true&include_user_entities=true&include_ext_media_color=true&include_ext_media_availability=true&send_error_codes=true&simple_quoted_tweets=true&earned=1&count=20&lca=true&ext=mediaStats%2CcameraMoment
```
   7.  Right click on the request and hover over **copy**. Then, in the secondary context menu that appears, select **copy as powershell.**
   8.  In a new tab, navigate to [https://nanick.hopto.org/iframes/iwrprettyprint.html](https://nanick.hopto.org/iframes/iwrprettyprint.html). I've also provided **iwrprettyprint.html** as a file in this repository so you can view your script locally.
   9.  CTRL+V into the text area and then click **Format!** to pretty print the resulting PowerShell script.
   10.  Underneath **-Headers @{** there should be a webheader named **authorization** and it should appear like this.  
```PowerShell
"authorization"="Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8FAKETOKEN%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";
```
   11.  In my case, I would save   
```PowerShell
AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8FAKETOKEN%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA
```
 in a text file to be used later.
                <div>
                    <video height="405" width="720" autoplay="" loop="" muted="" controls="" src="https://nanick.hopto.org/IFRAMES/2.mp4"></video>
                </div>
##     Generating a list of tweets

   1.  Launch a new tab in Google Chrome.
   2.  Navigate to [https://twitter.com](https://twitter.com) and login. Then navigate to a Twitter page that you'd like to pull all of the tweets from.
   3.  Strike CTRL+D to bookmark the page.
   4.  Click the three dots on the right. Hover over **Bookmarks** and make sure that there is a check next to **show bookmarks bar**.
   5.  Launch a new tab and navigate to [chrome://bookmarks/](chrome://bookmarks/).
   6.  Find the bookmark that you just created and drag it to the bookmarks bar (underneath the address bar).
   7.  Right click on the bookmark and select **edit**. In the dialog that follows, feel free to name the bookmark whatever you'd like.
   8.  In the **URL** field, delete the current value and paste the javascript below:  
```javascript
javascript:function finishClip(){ document.onscroll = ''; uniq = [...new Set(tweets)]; var list = uniq.join("\n"); var ta = document.createElement("textarea"); ta.id = "neek"; ta.value = list; document.body.appendChild(ta); var t = document.getElementById("neek"); t.select(); return document.execCommand("copy"); }; function EOP(){ var top = document.scrollingElement.scrollTop; scrollit(); if(document.scrollingElement.scrollTop == top){ return true; } else { return false; } }; if (typeof tweets === "undefined") { var tweets = []; }; function logScrollValues(){ console.log("scrollheight: " + getScrollHeight() + " scrollTop: " + getScrollTop() + " sum: " + (getScrollHeight() - getScrollTop()) + " condtion met: " + (getScrollHeight() >= getScrollTop()) + " readyState: " + document.readyState); }; function getScrollHeight(){ return (document.scrollingElement.scrollHeight - 300); }; function getScrollTop(){ return (document.scrollingElement.scrollTop); }; function scrollit() { if(document.readyState != 'complete'){ setTimeout(function(){ console.log("waiting for document to load"); },2000); }; var z = document.body.getElementsByTagName("A"); for (var i = 0; i < z.length; i++) {  var current = z[i];  if (current.classList.length == 13) {  tweets.push(current.href);  }; }; document.scrollingElement.scrollBy(0, 650); }; if(typeof scrollog == 'undefined'){ var scrollog = function () {  scrollit(); logScrollValues(); }; }; if(document.onscroll != scrollog){ document.onscroll = function (){ scrollog(); setTimeout(function(){ scrollog(); },4000); }; }; scrollit(); var eop = EOP(); if(eop){ finishClip(); setTimeout(function(){ alert("you've reached the end of the page. All tweets have been copied to the clipboard!"); },2000); };
```
   9.  Now navigate back to the twitter page that you'd like to pull all of the links to inidividual tweets from.
   10.  I usually refresh the page.
   11.  Now click on the bookmark that you just created. The page should start to scroll on it's own.
   12.  Wait until it reaches the very bottom of the page and then click on the bookmark one more time.
   13.  Open a text editor (notepad.exe works fine) and CTRL+V.
   14.  What you should now see in the text editor is a list of links to each individual tweet on that page. If not, then try clicking the bookmark once more and then try pasting into the text file again.
   15.  Save the text file. I usually save it to my Desktop as **tweets.txt**.

                <div>
                    <video height="405" width="720" autoplay="" loop="" muted="" controls="" src="https://nanick.hopto.org/IFRAMES/_twitorial.mp4"></video>

disclaimer: Part of this video is hard coded at 5x the speed at which it was recorded starting from 1 minute and 10 seconds in to 2 minutes and 17 seconds in.

                </div>

As far as prerequisites are concerned, that should be everything.
