-- applescript
-- Runs the bundled test.sh (located at Contents/Resources/test.sh inside this .app)
-- with administrator (sudo) privileges, and displays its ~20 lines of output.

-- Resolve the path to test.sh inside this app bundle's Resources folder
set resourcePath to (POSIX path of (path to resource "macos-CIS-query-Tahoe-os26.sh"))

-- Make sure it's executable (in case permissions were stripped during copy/build)
try
	do shell script "chmod +x " & quoted form of resourcePath
on error errMsg
	display dialog "Could not prepare script to run:" & return & return & errMsg buttons {"OK"} default button "OK" with icon stop
	return
end try

-- Run the script with administrator privileges, capturing its output
try
	set scriptOutput to do shell script (quoted form of resourcePath) with administrator privileges
	display dialog scriptOutput buttons {"OK"} default button "OK" with title "Current Hardening Settings"
on error errMsg number errNum
	if errNum is -128 then
		-- User clicked Cancel on the password prompt
		display dialog "Administrator authorization was cancelled. Script was not run." buttons {"OK"} default button "OK" with icon caution
	else
		display dialog "Script failed to run:" & return & return & errMsg buttons {"OK"} default button "OK" with icon stop
	end if
end try