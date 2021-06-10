<h2>Arturo Verdin <arturove@usc.edu> 6590836368</h2>
<h3>Note: I used the -m in server.py and client.py for the message sending.
    I also used some file pathing. Hopefully that does not provide trouble when testing. </h3>

Commands I used:
python3.8 ca.py -p 40000
python3.8 server.py -p 40002 -pp 40000 -ss 127.0.0.1 -m yo
python3.8 client.py -s 127.0.0.1 -p 40002 -ss 127.0.0.1 -pp 40000 -m hello

