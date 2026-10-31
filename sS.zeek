type ipRec: record {
    noticeCounter: int;
    openPorts: set[port];
    closedPorts: set[port];
};

global a: table[addr] of table[addr] of ipRec;
global threshold: int = 100;

redef enum Notice::Type += {
	sS_Port_Scanning,
};

function raiseNotice(orig_host: addr, resp_host: addr)
	{
	local i: int = |a[orig_host][resp_host]$openPorts| + |a[orig_host][resp_host]$closedPorts|;
	if (modulo(i, threshold) == 0)
	{
		NOTICE([$note=sS_Port_Scanning,
        $msg=fmt("%s appears to port scanning using nmap -sS. Amount of ports likely scanned %d. Notice nr. %d. Openports %d",
                 orig_host, 
				 i, 
				 a[orig_host][resp_host]$noticeCounter, 
				 |a[orig_host][resp_host]$openPorts|)]);
		a[orig_host][resp_host]$noticeCounter += 1;
	}
	}

event connection_reset(c : connection)
	{
	local originator_host: addr = c$id$orig_h;
	local responder_host: addr = c$id$resp_h;
    local responder_port: port = c$id$resp_p;
    local empty_ports: set[port] = set();
    
	if ( c$history == "ShR" ) #
		{
		if ( originator_host !in a )
			{
				a[originator_host] = table();
				a[originator_host][responder_host] = [$noticeCounter=0, $openPorts=set(responder_port), $closedPorts=empty_ports];
			}
		else if ( responder_host !in a[originator_host] )
			{
				a[originator_host][responder_host] = [$noticeCounter=0, $openPorts=set(responder_port), $closedPorts=empty_ports];
			}
		else if ( responder_port !in a[originator_host][responder_host]$openPorts ) # added this so we do not count the same open port again and again
			{
				a[originator_host][responder_host]$openPorts += set(responder_port);
				raiseNotice(originator_host, responder_host);
			}
		}
	}
	
event connection_rejected(c: connection)
    {
    local originator_host: addr = c$id$orig_h;
    local responder_host: addr = c$id$resp_h;
    local responder_port: port = c$id$resp_p;
    local empty_ports: set[port] = set();

    if ( originator_host !in a )
    {
        a[originator_host] = table();
		a[originator_host][responder_host] = [$noticeCounter=0, $openPorts=empty_ports, $closedPorts=set(responder_port)];
		return;
	}
	
	if ( responder_host !in a[originator_host] )
	{
		a[originator_host][responder_host] = [$noticeCounter=0, $openPorts=empty_ports, $closedPorts=set(responder_port)];
		return;
	}
	
	if ( responder_port !in a[originator_host][responder_host]$closedPorts ) # added this check so we only count a closed port the first time we see it
		{
			a[originator_host][responder_host]$closedPorts += set(responder_port);
			raiseNotice(originator_host, responder_host);
		}

    }

event zeek_done()
    {
    for ( orig_host in a )
        {
        for ( resp_host in a[orig_host] )
            {
            local r: ipRec = a[orig_host][resp_host];

            print fmt("%s -> %s: Closed Ports=%d, Amount of notices=%d, Open ports=%d",
                      orig_host, resp_host,
                      |r$closedPorts|, r$noticeCounter, |r$openPorts|);

            }
        }
    }
