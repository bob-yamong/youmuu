![실행결과](./image.png)

```
sudo apt-get install libcurl4-openssl-dev libjson-c-dev zlib1g-dev libpq-dev libpqxx-dev
```

```
cd libpqxx
git checkout 7.5.1
mkdir build && cd build \
    && cmake .. \
    && make -j$(nproc) \
    && sudo make install \
    && cd ../.. \
    && ldconfig
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
```