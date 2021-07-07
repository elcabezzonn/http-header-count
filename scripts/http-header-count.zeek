##! This is a modification to the header-names.zeek script. The objective of this script is to count the headers of the http request from the originator. This could help with identifying anomalous activity in your environment. 
@load base/protocols/http

module HTTP;

export {
	redef record Info += {
		## The vector of HTTP header names sent by the client.  No header 
		## values are included here, just the header names.
		client_header_names:  vector of string &optional;
		client_header_count:  count &log &optional;	
	};

	## A boolean value to determine if client headers are to be logged.
	option log_client_header_names = T;
	option log_header_count = T;

}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( ! c?$http )
		return;

	if ( is_orig )
		{
		if ( log_client_header_names && log_header_count)
			{
			if ( ! c$http?$client_header_names && ! c$http?$client_header_count )
				c$http$client_header_names = vector();
				c$http$client_header_names += name;
				c$http$client_header_count = |c$http$client_header_names|;

		}
	}
}
