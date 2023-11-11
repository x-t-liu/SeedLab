FROM handsonsecurity/seed-server:apache-php

ARG WWWDIR=/var/www/xtliu2023

COPY ./index.html ./index_red.html $WWWDIR/
COPY ./xtliu2023_apache_ssl.conf /etc/apache2/sites-available
COPY ./csu_apache_ssl.conf /etc/apache2/sites-available
COPY ./certs/server.crt ./certs/server.key  /certs/
COPY ./certs/university.crt ./certs/university.key  /certs/

RUN  chmod 400 /certs/server.key \
     && chmod 400 /certs/university.key \
     && chmod 644 $WWWDIR/index.html \
     && chmod 644 $WWWDIR/index_red.html \
     && a2enmod ssl \
     && a2ensite xtliu2023_apache_ssl  \
     && a2ensite csu_apache_ssl 

CMD  tail -f /dev/null

