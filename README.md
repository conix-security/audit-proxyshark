#Proxyshark

*This document is based on the current development version of proxyshark and
should be considered as a technical specification document. As a consequence,
a number of features could be absent from the last stable release and marked
as [DEPRECATED] or [UPCOMING] in the following documentation.*

First of all, you have to know that *proxyshark* can be used in 4 different
modes:

**View mode**: all you have to do here is run *proxyshark* with the appropriate
arguments and watch the result in your favorite shell. You can setup filters
and schedule simple actions based on given conditions, but nothing too
complicated. For example, you can define an action to automatically replace by
a given value all occurrences of a given value in a given field. You can switch
to this mode by running *proxyshark* with the [--run](#runarg)
argument or by pressing Ctrl-D in interactive mode (see below).

**Interactive mode**: this mode is very close to the view mode except that you
can use the embedded shell to change settings and manipulate packets at
run-time. It gives you complete control over what *proxyshark* is doing.
To switch to interactive mode, just run *proxyshark* without the
[--run](#runarg) argument or press Ctrl-C in view mode. Available
commands are listed [below](#console).

**Scripting mode [UPCOMING]**: you can specify a Python script as [last
command-line argument](#script). All commands available in interactive mode are
also available here. Note that you will switch to view mode after the script
being interpreted.

**Web-driven mode**: a bit more complicated, here *proxyshark* will generate
an HTTP POST to its own web service each time a packet is captured. The idea
is to send this request through a local web proxy to handle captured packets
through a GUI. This way, all powerful tools provided by such proxy will be
available (for example, Scanner, Intruder and Repeater from
[Burp Suite Pro](http://portswigger.net/)).
Of course, you will need an appropriate extension if you don't want to
manipulate raw HTTP requests. Fortunately, an extension for Burp Suite Pro will
be released with *proxyshark* **[UPCOMING]**. To use this mode, you have either
to pass the [--web-driven](#webarg) argument or to [enable it](#setweb) from
the interactive console. Note that web-driven mode can be used in parallel with
any other mode.

##Command-line arguments

To use *proxyshark*, simply run the Python script *proxyshark*.py.

The following arguments are available (all optional):

####-h | --help

Print a short help describing the available
command-line arguments.

####-v | --verbose

Can be specified several times to increase the
[verbosity level](#setverbosity).

Default is on (level 1) in view mode and off (level 0)
in interactive mode.

####-e | --ethernet

Turn on [Ethernet mode](#setethernet).

Default is off.

####-q | --queue-num &lt;queue-num&gt;

Set the netfilter [queue number](#setqueuenum) to use.

Default is 1234.

####-t | --tshark-dir &lt;tshark-dir&gt;

Set the location of the [tshark](#settshark) binary to use for packet
dissection.

Default is ./bin/&lt;arch&gt; where &lt;arch&gt; is the
current architecture (i686, x86_64,
etc).

<a name="webarg"></a>
####-w | --web-driven [&lt;bind-ip&gt;]:[&lt;bind-port&gt;]:[&lt;proxy-ip&gt;]
:[&lt;proxy-port&gt;]

Turn on [web-driven mode](#setweb).

Default is off. If enabled, default parameters are:

* &lt;bind-ip&gt; = 127.0.0.1
* &lt;bind-port&gt; = 1234
* &lt;proxy-ip&gt; = 127.0.0.1
* &lt;proxy-port&gt; = 8080

Note that all of them are optional and that ::: is
allowed.

####-c | --capture-filter &lt;capture-filter&gt;

Set the [capture filter](#setcapture).

Default is no filter (or any, or ip).

####-p | --packet-filter &lt;packet-filter&gt;

Set the [packet filter](#setpacket).

Default is no filter (or any, or ip).

####-f | --field-filter &lt;field-filter&gt;

Set the [field filter](#setfield) (only available in web-driven
mode).

Default is no filter (or .*).

<a name="runarg"></a>
####-r | --run

Automatically run capture at start, then switch to view
mode.

Default is off.

####-b | --breakpoint &lt;packet-filter&gt;

Define a default [breakpoint](#breakpoint) based on the given packet
filter.

Default is no breakpoint.

####-a | --action &lt;expression&gt;

An [action](#action) to run when the default breakpoint is reached.

Default is no action.

<a name="script"></a>
####[&lt;filename&gt;]

An optional script to run at start (in scripting mode)

**[UPCOMING]**.

Default is no script.

######Examples

Run *proxyshark* in interactive mode:


    python proxyshark.py --verbose

Capture SIP traffic in web-driven mode with local web proxy running on port 8888
(view mode):

    python proxyshark.py -v --capture-filter 'port 5060' --packet-filter 'sip' --web-driven :::8888 --run

Replace all HTTP responses by HTTP 500 errors (view mode):

    python proxyshark.py -v -c 'port 80' -p 'http.response.code' -r --breakpoint 'any' --action 'bpkt["http.response.code"]=500 ; bpkt.accept()'

<a name="console"></a>
##Interactive console

Several commands are available:

####h|help [command]

Print a short help describing the available commands.

<a name="info"></a>
####i|info [parameter]

Print information about the current program state:

* Verbosity level
* Ethernet mode
* Netfilter queue
* Tshark directory
* Web-driven mode
* Filters
* Breakpoints
* Actions
* Cache

You can specify an optional parameter to get information about it.
Available parameters are:

* verbosity
* ethernet
* queue-num
* tshark-dir
* web-driven
* bind ip
* bind port
* proxy ip
* proxy port
* capture filter
* packet filter
* field filter
* breakpoint
* action
* cache

<a name="setverbosity"></a>
####set verbosity 0|1|2|3

Set the verbosity level to one of the following values:

* 0 for errors only (quiet mode)
* 1 for information and warnings
* 2 for debug
* 3 for more debug

<a name="setethernet"></a>
####set ethernet off|on|0|1

Enable or disable Ethernet mode.

If enabled, an Ethernet layer will be automatically generated for all captured
packets. Otherwise, packets will start at layer 3 (IP). Enabling this mode is
required only if you plan to replay packets at layer 2.

<a name="setqueuenum"></a>
####set queue-num &lt;queue-num&gt;

Set the netfilter queue to use.

This option specifies which queue to use and to send the queue'd data to.
The queue number is a 16 bit unsigned integer, which means it can take any value
between 0 and 65535.

<a name="settshark"></a>
####set tshark-dir &lt;tshark-dir&gt;

Set the location of the tshark binary to use for packet dissection.

If not found, tshark is taken from $PATH.

<a name="setweb"></a>
####set web-driven off|on|0|1

Enable or disable web-driven mode.

In this mode, an embedded web server will wait for incoming requests from
*proxyshark* itself. The idea is to ask *proxyshark* to call this web service
each time a packet is captured so that we can use a tool such as Burp Suite Pro
to handle it.


####set web-driven [&lt;bind-ip&gt;]:[&lt;bind-port&gt;]:[&lt;proxy-ip&gt;]

This is a shortcut to enable web-driven mode and set bind IPs / ports.

####set bind ip &lt;bind-ip&gt; | set bind port &lt;bind-port&gt; |
set proxy ip &lt;proxy-ip&gt; | set proxy port &lt;proxy-port&gt;

Set parameters of the web-driven mode. The available parameters are:

* &lt;bind-ip&gt;: binding address of the embedded web server
* &lt;bind-port&gt;: listening port of the embedded web server
* &lt;proxy-ip&gt;: IP address of the web proxy to use
* &lt;proxy-port&gt;: port of the web proxy to use

<a name="setcapture"></a>
####set capture filter &lt;capture-filter&gt;

Set the current capture filter.

This filter acts at a netfilter level to select which packets have to be
captured. Basically, you just have to provide a BPF filter and *proxyshark*
will use it to generate appropriate iptables rules targeting the NFQUEUE target.

The formal grammar is:

* CaptureFilter =&gt; [any | BooleanKeyword]
* BooleanKeyword =&gt; not Keyword | Keyword and Keyword | Keyword or Keyword
* Keyword =&gt; Device | Host | Network | Port | Protocol
* Device =&gt; [in | out] dev BooleanValue
* Host =&gt; [src | dst] host BooleanValue
* Network =&gt; [src | dst] net BooleanValue
* Port =&gt; [src | dst] port BooleanValue
* Protocol =&gt; ip | icmp | tcp [Port] | udp [Port]
* BooleanValue =&gt; not &lt;value&gt; | &lt;value&gt; and &lt;value&gt; |
&lt;value&gt; or &lt;value&gt;

Where values can be:

* DeviceValue =&gt; [alphas][alphanums-._]*
* HostValue =&gt; IpAddress | [alphas][alphanums-._]*
* NetworkValue =&gt; IpAddress / ( IpAddress | [nums]{1,2} ) | IpAddress netmask
IpAddress
* PortValue =&gt; [nums]{1,5}
* With:
* IpAddress =&gt; [nums]{1,3} . [nums]{1,3} . [nums]{1,3} . [nums]{1,3}

######Examples

Capture *Google Docs* traffic:

    host docs.google.com and tcp port 80 or 443

    [DEBUG] name 'docs.google.com' resolved:
    [DEBUG] - 173.194.40.134
    [DEBUG] - 173.194.40.129
    [DEBUG] - 173.194.40.130
    [DEBUG] - 173.194.40.135
    [DEBUG] - 173.194.40.131
    [DEBUG] - 173.194.40.137
    [DEBUG] - 173.194.40.128
    [DEBUG] - 173.194.40.136
    [DEBUG] - 173.194.40.133
    [DEBUG] - 173.194.40.142
    [DEBUG] - 173.194.40.132
    [DEBUG] iptables -t filter -A proxyshark5022 -j NFQUEUE --queue-num 1234
    [DEBUG] iptables -t filter -A proxyshark6242 -p tcp --dport 443 -j proxyshark5022
    [DEBUG] iptables -t filter -A proxyshark6242 -p tcp --sport 443 -j proxyshark5022
    [DEBUG] iptables -t filter -A proxyshark6242 -p tcp --dport 80 -j proxyshark5022
    [DEBUG] iptables -t filter -A proxyshark6242 -p tcp --sport 80 -j proxyshark5022
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.132 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.132 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.142 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.142 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.133 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.133 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.136 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.136 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.128 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.128 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.137 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.137 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.131 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.131 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.135 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.135 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.130 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.130 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.129 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.129 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -d 173.194.40.134 -j proxyshark6242
    [DEBUG] iptables -t filter -A proxyshark9104 -s 173.194.40.134 -j proxyshark6242
    [DEBUG] iptables -t filter -I INPUT 1 -j proxyshark9104
    [DEBUG] iptables -t filter -I OUTPUT 1 -j proxyshark9104
    [DEBUG] iptables -t filter -I FORWARD 1 -j proxyshark9104

Capture all DNS traffic, and SIP requests from 10.0.0.0/8 to 1.2.3.4 or 2.3.4.5
on network device eth1:

    dev eth1 and (udp port 53 or dst port 5060 and src net 10.0.0.0/8 and dst host 1.2.3.4 or 2.3.4.5)

    [DEBUG] iptables -t filter -A proxyshark5605 -j NFQUEUE --queue-num 1234
    [DEBUG] iptables -t filter -A proxyshark5297 -d 2.3.4.5 -j proxyshark5605
    [DEBUG] iptables -t filter -A proxyshark5297 -d 1.2.3.4 -j proxyshark5605
    [DEBUG] iptables -t filter -A proxyshark6208 -s 10.0.0.0/8 -j proxyshark5297
    [DEBUG] iptables -t filter -A proxyshark3724 -p udp --dport 5060 -j proxyshark6208
    [DEBUG] iptables -t filter -A proxyshark3724 -p tcp --dport 5060 -j proxyshark6208
    [DEBUG] iptables -t filter -A proxyshark3724 -p udp --dport 53 -j proxyshark5605
    [DEBUG] iptables -t filter -A proxyshark3724 -p udp --sport 53 -j proxyshark5605
    [DEBUG] iptables -t filter -A proxyshark9821 -o eth1 -j proxyshark3724
    [DEBUG] iptables -t filter -A proxyshark9821 -i eth1 -j proxyshark3724
    [DEBUG] iptables -t filter -I INPUT 1 -j proxyshark9821
    [DEBUG] iptables -t filter -I OUTPUT 1 -j proxyshark9821
    [DEBUG] iptables -t filter -I FORWARD 1 -j proxyshark9821

<a name="setpacket"></a>
####set packet filter &lt;packet-filter&gt;

Set the current packet filter.

This filter is almost like a Wireshark
[display filter](http://wiki.wireshark.org/DisplayFilters). You can use it to
select captured packets based on dissection criteria.

The formal grammar is:

* PacketFilter =&gt; [any | BooleanCondition]
* BooleanCondition =&gt; not Condition | Condition and Condition | Condition or
Condition
* Condition =&gt; Operand [Operator Value]
* Operand =&gt; raw | Item | [( len | nb ) ( Item )]
* Item =&gt; ItemName [[ AttributeName ]] [[ SliceKey ]]
* ItemName =&gt; [alpha._]+
* AttributeName =&gt; [alpha]+
* SliceKey =&gt; [-nums]* : [-nums]*
* Operator =&gt; == | = | != | ^= | *= | $= | &lt;= | &lt; | &gt;= | &gt;
* Value =&gt; QuotedValue | UnquotedValue
* QuotedValue =&gt; "[printable]+" | '[printable]+'
* UnquotedValue =&gt; [printable_without_space]+

Where operators are:

* Equals: == or =
* Differs: !=
* Begins with: ^=
* Contains: *=
* Ends with: $=
* Lower than or equal: &lt;=
* Lower than: &lt;
* Greater than or equal: &gt;=
* Greater than: &gt;

######Examples

Select ICMP packets with TTL lower than 32:

    icmp and ip.ttl < 32

Select packets bigger than 1KiB containing raw string '&lt;/html&gt;\r\n':

    len(raw) > 1024 and raw*=<html>\r\n'

Select HTTP requests with URI starting with /index.php?page= and User-Agent
shorter than 10 characters:

    http.request.method=GET and http.request.uri^=/index.php?page= and len(http.user_agent) < 10

<a name="setfield"></a>
####set field filter &lt;field-filter&gt;

Set the current field filter.

This filter is only available in web-driven mode. It's just a
[regular expression](http://docs.python.org/2/howto/regex.html)
to select which protocols and fields are sent to the web proxy (ie which ones
will be editable/repeatable through the GUI).

Note that if no ^ or $ characters are found, they will be automatically added
at the beginning or at the end of the filter.

######Examples

Forward only the fields from the SIP layer:

    sip.*

Forward IP and TCP protocols (not the fields), and all the fields from the
HTTP layer:

    ip$|tcp$|http.*

<a name="breakpoint"></a>
####b|breakpoint [add|del] [&lt;breakpoint-id&gt;] [&lt;packet-filter&gt;]

Breakpoints are triggered when a given [packet filter](#setpacket) matches an
incoming packet. You can define an (or several) [action](#action) to alter the
packet, accept it, drop it, replay it, etc.

If a breakpoint with no associated action triggers, the capture will stop, and
the packet will be editable manually. In that case, you will switch to
interactive mode automatically if needed.

This command can be used in several different ways:

* If no argument is given, print a list of all existing breakpoints
(equivalent to [info breakpoint](#info)).
* If a breakpoint identifier is given, print the packet filter associated to
this breakpoint. The breakpoint identifier must be an arbitrary string
containing letters, digits, dashes, dots or underscores.
* If the keyword add, a breakpoint id and a packet filter are given, create a
new breakpoint based on the given identifier and filter.
* If the keyword add and a packet filter are given, create a new breakpoint and
name it automatically.
* If the keyword del and a breakpoint id are given, delete the breakpoint.

######Examples

Display the packet filter of ID some_id:

    >>> breakpoint some_id

Add a new breakpoint without specifying an ID:

    >>> breakpoint add "icmp and ip.src == 8.8.8.9"

Delete the breakpoint of id bp_icmp:

    >>> breakpoint del bp_icmp


####en|enable &lt;breakpoint-id&gt;

Enable an existing breakpoint.

####dis|disable &lt;breakpoint-id&gt;

Disable an existing breakpoint.

<a name="action"></a>
####a|action [add|del|bind|unbind] [&lt;action-id&gt;] [to]
[&lt;breakpoint-id&gt;] [&lt;expressions&gt; ...]

Actions are Python expressions to be run when a breakpoint is triggered.
Commands and [functions](#functions) available in interactive mode are also
available in such expressions.

This command can be used in several different ways:

* If no argument is given, print a list of all existing actions
(equivalent to [info actions](#info)).

* If only an action identifier is given, print the breakpoint
and the Python expression associated to this action
The action identifier must be an arbitrary string containing
letters, digits, dashes, dots or underscores.

* If the keyword del and an action id are given, delete an existing action

* If  the keyword bind, an action id and a breakpoint id are given, rebind an
existing action to an existing breakpoint

* If the keyword unbind, and an action id are given, unbind an
existing action from its breakpoint

* If the keyword add, an action id, the keyword to, a breakpoint id and
expressions are given, create a new action based on the given expressions and
identifiers, and bind it to the breakpoint.
  * If the action id is omitted, the action will be named automatically.
  * The keyword to and the breakpoint id can also be omitted: this will
create a new action without binding it to any breakpoint

An action can only be bound to one breakpoint at a time, but several actions
can be bound to a single breakpoint.

######Examples:

Create an action without binding it to a breakpoint:

    >>> action add a1 "some expression"

Create an action composed of several expressions, and name it automatically:

    >>> action add to default "bpkt['icmp.type'] = 8" "bpkt.accept()"

Create an action and bind it to the breakpoint 'default'

    >>> action add a2 to default "print 'triggered!'"

Bind, then unbind an action:

    >>> action bind a1 default
    >>> action unbind a1


####r|run [&lt;capture-filter&gt;] [&lt;packet-filter&gt;]
[&lt;field-filter&gt;]

Run a new capture (drop previously captured packets).

Filters can be provided to override current [settings](#setcapture).

You can also run a capture at start with the [--run](#runarg) command-line
argument.

####p|pause

Pause the current capture.

####c|continue

Continue the current capture.

####s|stop

Stop the current capture, without removing previously captured packets

####q|queue

Return a reference to the captured packets list

######Examples
Get HTTP packets from 1.2.3.4:

    >>> packets = queue['ip.src=1.2.3.4 and http']

####p|packet

A special variable containing the last packet (equivalent to queue[-1]).

####bpkt

A special variable pointing to the last packet that triggered a breakpoint. It
can be used to manipulate a packet when a breakpoint is triggered, in
interactive mode or inside an action

####pe|pending

Display all the packets that have currently no verdict set. This command also
sets the special variable "_"

<a name="cmd_accept"></a>
####acc|accept [&lt;packet filter&gt;]|[all]

Set the verdict 'accept' to all the packets matching the given packet filter.
The keyword 'all' is accepted. If no packet filter is passed, accept all pending packets.

<a name="cmd_drop"></a>
####dr|drop [&lt;packet filter&gt;]|[all]

Set the verdict 'drop' to all the packets matching the given packet filter.
The keyword 'all' is accepted. If no packet filter is passed, drop all pending packets.

####rm|remove [&lt;packet filter&gt;]|[all]

Remove from the queue all the packets matching the given filter. The keyword
'all' is accepted. If no packet filter is passed, remove all packets.

Note that the verdict drop will be set on all removed pending packets.


######Examples

After a break on an HTTP packet, change the User-Agent and accept the packet:

    >>> bpacket['http.user_agent'] = 'User-Agent: My Custom User-Agent\r\n'
    >>> bpacket.accept()

Or drop the current packet and replay it with another server as destination:

    >>> bpacket['http.host'] = 'Host: 2.3.4.5\r\n'
    >>> bpacket.accept()

####flush

Flush internal cache to free memory (captured packets are not removed).

####x|exit

Stop the current capture and quit *proxyshark*.


##Manipulating a packet

A *proxyshark* packet is represented by the class DissectedPacket. See
help(DissectedPacket) for a complete list of accessible methods.

Packets are stored using PDML-like format. You can access its content using
this format's attributes:

* name
* showname
* value
* show
* ...

####Displaying a packet

There are several ways to display a packet and its content.

In interactive mode, you can simply type the variable name, or call *repr* on
the variable, to get a one-line representation of the packet

If you want a more detailed description, simply print the packet
or call *str* on it.

######Examples

    >>> bpkt
    >>> print repr(bpkt)
    >>> print bpkt

####Changing a field value

The following syntax allows you to change the value of a given field:
packet[&lt;field&gt;] = &lt;new value&gt;

######Examples

    >>> bpkt['dns.qry.name'] = '\x06google\x03com\x00'
    >>> queue[0]['data.data'] = 'New ICMP payload'

####Setting a verdict

A verdict can be set on a packet using the following methods:

* DissectedPacket.accept(self)
* DissectedPacket.drop(self)

######Examples:

Drop the first packet of the queue:

    >>> queue[0].drop()

Accept the last captured packet:

    >>> pkt.drop()

####Replaying a packet

You can replay a single packet several times using DissectedPacket's method
replay. You can provide it with several arguments:

* *layer*: from which layer the data should be replayed (see below).
* *repeat*: the number of times the packet should be replayed, default is 1.
* *inter*: the time to wait between two packets are sent. This is similar to
the inter parameter of scapy's function send.

The currently accepted values for parameter *layer* are 2, 3 and 4.

Replaying packet at level 2  is currently equivalent to replaying them at
level 3.

Replaying packet at level 3 is the default mode. This will simply use the
updated raw data, and send it over the network.

Layer 4 will make sure a different source port is used, and will open a new
TCP connection if TCP is used **[UPCOMING]**. This allows you to replay
(for instance) an HTTP request, or any other request based on TCP. The replayed
payload will start at layer 5, i.e any change in layers 3 and 4
will not be reflected.

######Examples

    >>> bpkt.replay(layer=3, repeat=10, inter = .1)
    >>> bpkt.replay(4)

##Using a list of packets

The class DissectedPacketList is used to store all the captured packets.
It provides several useful methods:


####Displaying the list

In interactive mode, call *repr* on the list to get the one-line representations
of each packets it contains. Call *str* on it to get the full content.

####Accepting packets

You can accept packets using the method accept(self, packet_filter). This is
actually the same as using the command [accept](#cmd_accept)
from interactive mode.

####Retrieving the accepted packets

Use DissectedPacketList's method accepted(self).

####Dropping packets

You can drop packets using the method drop(self, packet_filter). This is
actually the same as using the command [drop](#cmd_drop) from interactive mode.

####Retrieving the dropped packets

Use DissectedPacketList's method dropped(self).

####Removing packets

You can remove packets from a list using a packet filter (or the keyword all),
and the method remove(self, packet_filter).

######Examples

    >>> queue.remove('dns.qry.name == "google.nz"')

####Getting the length of the list

You can either use the method length(self), or call len(list).

####Filtering the list

You can get a sublist of a given DissectedPacketList by calling the method
where(self, packet_filter). This methods takes a packet filter and returns a
DissectedPacketList containing all the DissectedPackets that matched.

######Examples

Retrieve all the ICMP packets

    >>> icmp_pkts = queue.where('icmp')

####Selecting fields and values

Using the method DissectedPacketList.select(self, packet_filter), you can
select several fields / values, depending on the packet filter you used.

This method returns a list object that provides
[filtering methods](#filter_select)

######Examples

Get the type of each captured ICMP packets:

    >>> queue.select('icmp.type[show]')
    [['8'], ['0'], ['8'], ['0'], ['8'], ['0']]

Get each destination IP address (in hexa representation):

    >>> queue.select('ip.dst[value]')

Retrieve all DNS query names (returns a SelectList object):

    >>> queue.select('dns.qry.name')

<a name="filter_select"></a>
####Retrieving uniq fields/values

You can call the method uniq(self) on the object returned after a selection.

######Examples

Retrieve all unique types of ICMP packets encountered:

    >>> queue.select('icmp.type[show]').uniq()

####[UPCOMING] filtering methods

Other methods will be added when future version of *Proxyshark* are released:

* min()
* max()
* group()
* sort()
* limit()
* ...

<a name="functions"></a>
##Creating actions

Some features are accessible as function usable within actions or the embedded
shell. Most of them have the exact same behaviour as *Proxyshark*'s commands:

* pause()
* cont(), continue()
* accept(&lt;packet_filter&gt;)
* drop(&lt;packet_filter&gt;)
* uniq(&lt;field_name&gt;)
