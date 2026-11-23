# Site policy for the honeycow-zeek sidecar, loaded after `local`.

# Half-open TCP connections (a SYN with no handshake after it) are held for
# tcp_inactivity_timeout. At the 5 min default, state for a burst of them
# builds up for five full minutes. Measured by pcap replay: 30 s cuts that
# peak by more than half, and normal traffic keeps the same http/dns/ssl logs
# (idle connections over 30 s just span more conn.log rows).
redef tcp_inactivity_timeout = 30 sec;

# Rotate hourly into <stream>.<open-time>.log; the current file keeps its plain
# name (conn.log). Without rotation every log stays open for the whole run and
# a restart truncates it, deleting the record of whatever came before.
redef Log::default_rotation_interval = 1 hr;

# Rotation alone doesn't survive a SIGKILL (an OOM kill): the current file is
# still truncated on restart. With this on, Zeek keeps a .shadow.* file per open
# log, and on startup it renames any log the previous process left behind.
redef LogAscii::enable_leftover_log_rotation = T;
