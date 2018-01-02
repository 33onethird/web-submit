# web-submit
Simple flask based web server for submitting APK files and getting them analysed. 
This flask app uses a small sqlite3 DB to cache already analysed results.

Author: [aaron kaplan](https://github.com/aaronkaplan)


# How to run this program?

## DB initialisation & preparation steps

  1. Create a new empty hashes.db: ``rm -f hashes.db; sqlite3 hashes.db < db.sql``
  2. Make sure the new DB is accessible:
```
  sqlite3 hashes.db
  .schema
  select * from hashes
```

## Running the server / the flask app
  1. source the virtual env: ``source venv/bin/activate``
  2. tell flask which program is the main app: ``export FLASK_APP=server.py``
  3. run flask: ``flask run --port 8080``. Now flask will run the application on port 8080. However, by default it will only listen on localhost (127.0.0.1). In order to listen on all IP addresses, run it like so: ``flask run --port 8080 --host=0.0.0.0``. **Note**: this does not work on our WU server, since all ports are firewalled.
   If your server allows connections to port 8080 directly, you can now direct your browser towards: http://<yourserver>:8080/api/v1/submit
  4. If (as in our case) you can not connect to the server on port 8080 from outside, use this ssh forwarding trick:
```
   (on the server) flask run --port 8080
   (on the client) < in a different terminal window> ssh -L 8080:localhost:8080  datascience@svm-google.ai.wu.ac.at
```
Now direct your browser to localhost:8080/api/v1/submit.



