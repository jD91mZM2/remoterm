# remoterm

SSH-like application for remote support.

Differences:
 - Can only handle one connection.
 - Easier to set up.
 - Host can see typing live.
 - Not as reliable as good ol' SSH.
 - Password protected by a random password.

# Warning

This is **not** a perfect application. Don't expect it to be one.

Known flaws:
 - Client does not close until you try to send a message (which will fail).
 - Ctrl+C on the server lets fork leak.
 - Slow.
