@load base/protocols/conn/removal-hooks

module COTP;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register COTP for.
	const ports = {
		# TODO: Replace with actual port(s).
		12345/udp,
	} &redef;

	## Record type containing the column fields of the COTP log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		# TODO: Adapt subsequent fields as needed.

		## Request-side payload.
		request: string &optional &log;
		## Response-side payload.
		reply: string &optional &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into COTP logging.
	global log_cotp: event(rec: Info);

	## COTP finalization hook.
	global finalize_cotp: Conn::RemovalHook;
}

redef record connection += {
	cotp: Info &optional;
};

redef likely_server_ports += { ports };

# TODO: If you're going to send file data into the file analysis framework, you
# need to provide a file handle function. This is a simple example that's
# sufficient if the protocol only transfers a single, complete file at a time.
#
# function get_file_handle(c: connection, is_orig: bool): string
#	{
#	return cat(Analyzer::ANALYZER_COTP, c$start_time, c$id, is_orig);
#	}

event zeek_init() &priority=5
	{
	Log::create_stream(COTP::LOG, [$columns=Info, $ev=log_cotp, $path="cotp", $policy=log_policy]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_COTP, ports);

	# TODO: To activate the file handle function above, uncomment this.
	# Files::register_protocol(Analyzer::ANALYZER_COTP, [$get_file_handle=COTP::get_file_handle ]);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$cotp )
		return;

	c$cotp = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	Conn::register_removal_hook(c, finalize_cotp);
	}

function emit_log(c: connection)
	{
	if ( ! c?$cotp )
		return;

	Log::write(COTP::LOG, c$cotp);
	delete c$cotp;
	}

# Example event defined in cotp.evt.
event COTP::message(c: connection, is_orig: bool, payload: string)
	{
	hook set_session(c);

	local info = c$cotp;
	if ( is_orig )
		info$request = payload;
	else
		info$reply = payload;
	}

hook finalize_cotp(c: connection)
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	emit_log(c);
	}
