Sample AllJoyn mesh test client to demonstrate authentication bug

Run two instances of:
./ajmesh --send --secure --keyx

This is working scenario with ALLJOYN_SRP_KEYX authentication


Run two instances of:
./ajmesh --send --secure

This is failing scenario with ALLJOYN_SRP_LOGON authentication
