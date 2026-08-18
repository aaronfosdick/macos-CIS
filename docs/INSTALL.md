# Installation Instructions

**Download the Script**
Open this link in your browser:<br>
https://github.com/aaronfosdick/macos-CIS/blob/master/macos-CIS-apply-Tahoe-os26.sh<br>
In the upper right of the page, click on the small download icon to download the file to the Downloads folder on your laptop

<img src="downloadraw.png" alt="Download" width="50%">


**Open Finder -> Applications -> Utilities:** 

<img src="Utilities.png" alt="Screenshot 1" width="75%">


**Open the "Terminal" application:** 

<img src="terminal.png" alt="Screenshot 2" width="75%">


**Once Teminal is open, type in these three commands, press Return after each. (you can also copy/paste) :** 
```
cd Downloads
chmod +x macos-CIS-apply-Tahoe-os26.sh
sudo ./macos-CIS-apply-Tahoe-os26.sh
```
_enter your macbook password when prompted_

<img src="terminal1.png" alt="Screenshot 3" width="75%">


**The script will start and will ask you some questions: **
**Choose 1 to Apply all CIS changes:** 
<img src="terminal2.png" alt="Screenshot 4" width="75%">


**The script will ask a few more questions, default choices are in CAPS:**<br> 
Set Screen Saver inactivity to 600 seconds (10 minutes)<br>
Grace Period is the amount of time after the screen goes blank that it locks. Either 0 or 10 seconds is fine.<br>
Remote Login: No<br>
Automated Updates: Yes<br>
Other choices: Yes

<img src="terminal3.png" alt="Screenshot 5" width="75%">


**Once finished, you will see a prompt line with the "%". You can now quit the terminal application** 
<img src="terminal4.png" alt="Screenshot 6" width="75%">
