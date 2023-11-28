openssl req -batch -x509 -newkey rsa:2048 -keyout bob-key.pem -out bob.pem -days 365 -nodes
openssl req -batch -x509 -newkey rsa:2048 -keyout alice-key.pem -out alice.pem -days 365 -nodes
openssl req -batch -x509 -newkey rsa:2048 -keyout eve-key.pem -out eve.pem -days 365 -nodes
openssl x509 -outform der -in bob.pem -out bob.der
openssl x509 -outform der -in alice.pem -out alice.der
openssl x509 -outform der -in eve.pem -out eve.der
openssl rsa -outform der -in bob-key.pem -out bob-key.der
openssl rsa -outform der -in alice-key.pem -out alice-key.der
openssl rsa -outform der -in eve-key.pem -out eve-key.der
