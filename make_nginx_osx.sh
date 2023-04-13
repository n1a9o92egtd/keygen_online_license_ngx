#! /bin/sh

killall nginx
killall nginx
rm -rf third_party/pcre
tar -zxvf third_party/pcre-8.41.tar.gz -C third_party/
mv third_party/pcre-8.41 third_party/pcre
rm -rf third_party/openssl
tar -zxvf third_party/openssl-1.1.1k.tar.gz -C third_party/
mv third_party/openssl-1.1.1k third_party/openssl
rm -rf third_party/nginx_backtrace
tar -zxvf third_party/nginx_backtrace.tar.gz -C third_party/
sudo rm -rf /Users/www/nginx/
sudo mkdir /Users/www
sudo chown -R $USER /Users/www
./configure --prefix=/Users/www/nginx --with-pcre=third_party/pcre --with-http_ssl_module --with-openssl=third_party/openssl --add-module=third_party/nginx_backtrace --with-ld-opt="-lstdc++"  --add-module=online_license/ngx_license
make -j8
make install
make clean
rm -rf third_party/pcre
rm -rf third_party/openssl
rm -rf third_party/nginx_backtrace
