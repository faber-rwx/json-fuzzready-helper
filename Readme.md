# JSON FuzzReady Helper - Burp Repeater Extension
Author	: Francesco Oddo <francesco.oddo@mdsec.co.uk>

Intro
--
The extension creates a new tab under Repeater and recursively converts all non-string JSON fields, such as int or boolean, to string to make them fuzz-ready.

Problem
--
Say you have an example vulnerable app like the following. 


	$json = file_get_contents('php://input');
	$data = json_decode($json);

	passthru($data->a);
	passthru($data->b);

Both parameters are vulnerable to command execution. If the app was designed to send a JSON body as follows...

{"a":"string", "b":1}

...actively scanning either the whole request or the specific insertion points would only detect the parameter 'a' as vulnerable, since the parameter 'b' is not "stringified" thus unable to submit payloads to the server-side.


Extension Usage
--
Any request detected as having a JSON body within Repeater will trigger the creation of a new tab where all fiels are recursively converted to string. The extension supports complex JSON hierarchies with multiple nested dict/list levels.

To update the original request, simply change any field in the custom tab.

The request can then be fuzzed as usual (active scan or send to intruder -> actively scan insertion points).


