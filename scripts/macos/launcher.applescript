-- Network Traffic Analyzer launcher (built by scripts/install_app.sh).
-- Starts the analyzer in the background, opens the dashboard, and stops the
-- analyzer when you quit the app. Opening it again just reopens the dashboard.

property repoPath : "__REPO__"
property appPort : "8000"
property serverPID : ""

on sessionURL()
	set urlFile to (POSIX path of (path to home folder)) & "Library/Application Support/NetworkTrafficAnalyzer/session-" & appPort & ".url"
	try
		return do shell script "/usr/bin/head -n 1 " & quoted form of urlFile
	on error
		return ""
	end try
end sessionURL

on serverUp()
	try
		do shell script "/usr/bin/curl -fsS -o /dev/null --max-time 1 http://127.0.0.1:" & appPort & "/favicon.svg"
		return true
	on error
		return false
	end try
end serverUp

on openDashboard()
	set u to my sessionURL()
	if u is not "" then do shell script "/usr/bin/open " & quoted form of u
end openDashboard

on run
	if my serverUp() then
		-- Already running (for example from the terminal): just show it.
		my openDashboard()
		quit
		return
	end if
	set logFile to (POSIX path of (path to home folder)) & "Library/Logs/NetworkTrafficAnalyzer.log"
	-- Only the Python process goes to the background, with every stream detached, so
	-- "do shell script" returns at once with its process ID (needed to stop it on Quit).
	set cmd to "cd " & quoted form of repoPath & " || exit 1; PYTHONPATH=backend /usr/bin/nohup .venv/bin/python -m app --open --start --port " & appPort & " >> " & quoted form of logFile & " 2>&1 < /dev/null & echo $!"
	try
		set serverPID to do shell script cmd
	on error errMsg
		display alert "Network Traffic Analyzer couldn't start" message errMsg as critical
		quit
	end try
end run

on reopen
	-- Clicking the Dock icon or opening the app again shows the dashboard.
	my openDashboard()
end reopen

on idle
	-- If the analyzer stops on its own, close the app too.
	if serverPID is not "" then
		try
			do shell script "/bin/kill -0 " & serverPID
		on error
			set serverPID to ""
			quit
		end try
	end if
	return 5
end idle

on quit
	if serverPID is not "" then
		try
			do shell script "/bin/kill " & serverPID
		end try
	end if
	continue quit
end quit
