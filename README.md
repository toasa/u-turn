
使い方

```
$ gcc main.c -o main
$ sudo ./main
TUN device tun0 allocated. Waiting for packets...
```

別ターミナルを開き、nc で UDP パケットを投げる：

```
$ ./setup.sh
$ nc -u 10.0.0.2 5554
```