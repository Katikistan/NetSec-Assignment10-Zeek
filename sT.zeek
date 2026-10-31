
type ipRec: record {
    noticeCounter: int;
    openPorts: set[port];
    closedPorts: set[port];
    connCount: int &default=0; # counts matching connections, because the target only has 5 open ports
};

global a: table[addr] of table[addr] of ipRec;
global threshold: int = 100;

redef enum Notice::Type += {
	sT_Port_Scanning,
};

function raiseNotice(orig_host: addr, resp_host: addr)
	{
	a[orig_host][resp_host]$connCount += 1; # count this connection (not distinct ports like in -sS)
	if (a[orig_host][resp_host]$connCount >= threshold) # compare connCount with the threshold, we count connections
	{
		NOTICE([$note=sT_Port_Scanning,
        $msg=fmt("%s appears to port scanning using nmap -sT. Connections without data %d. Notice nr. %d",
                 orig_host, a[orig_host][resp_host]$connCount, a[orig_host][resp_host]$noticeCounter)]);
		a[orig_host][resp_host]$noticeCounter += 1; # The number of previous Notices goes up after each Notice
		a[orig_host][resp_host]$connCount = 0; # we start counting over after every Notice
	} # message shows connections without data instead of ports
	}

event connection_state_remove(c : connection) # changed to connection_state_remove, so the history is final when we check it
	{
	if ( ! c?$history || c$history != "ShAR" ) # only count history exactly ShAR (handshake finished, no data), to seperate -sT from -sS
		return;
	
	local originator_host: addr = c$id$orig_h;
	local responder_host: addr = c$id$resp_h;
    local responder_port: port = c$id$resp_p;
    local empty_ports: set[port] = set();
    
    if ( originator_host !in a )
    {
    	a[originator_host] = table();
		a[originator_host][responder_host] = [$noticeCounter=0, $openPorts=set(responder_port), $closedPorts=empty_ports];
	}
	
	if ( responder_host !in a[originator_host] )
	{
		a[originator_host][responder_host] = [$noticeCounter=0, $openPorts=set(responder_port), $closedPorts=empty_ports];
	}
	
	a[originator_host][responder_host]$openPorts += set(responder_port);
	raiseNotice(originator_host, responder_host); # Called for every ShAR connection (we dont check new-port), because we count connections
	
	}
	
# removed connection_rejected: closed ports look the same in -sS and -sT, so we do not count them
	
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
