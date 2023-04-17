# **Client for the IPK Calculator protocol**

## **Usage**
To use this program you need to specify server host name/IP address, port and mode (protocols of the Internet protocol suite.).
Either:
- tcp (Transmission Control Protocol)
- udp (User Datagram Protocol)
```./ipkcpc -h <host> -p <port> -m <mode>```
to compile the program you need to run:
```make```
Program includes header support for windows, but there is no cmake. So you need to compile it manually.

## **Example of usage**
If server is running on `localhost` on port `1234` in `tcp` mode, then we can run the program with:
```./ipkcpc -h localhost -p 1234 -m tcp```
Where we should start conversation with `HELLO` and then continue accordingly
for udp, example would be:
```./ipkcpc -h localhost -p 1234 -m udp```

## **Code description**
Firstly the program parses and checks the argments. Then by using function `gethostbyname()` we will get adress of host, then we will find IP adrees of host and initialize server address. Till now it was the same for tcp and udp.
### - tcp:
If mode was selected as `tcp` we continue in function `tcp_mode()`. There we create client socket, and connect to the server. Now we enter while cycle which ends when server responds with message `BYE\n`. In cycle we null buffer with function `bzero()` and then we read client's message from stdin, and put the message to our inicialized buffer, the message is sent to server with `send()` function.We again null our buffer and then we wait for response from server with `recv()` function. Server response is printed to stdout via our buffer. Throughout this loop, program is also waiting for interrupt signal `(C-c)` via `signal()` function. Where if client sends interrupt signal, the program sends `BYE` to server and awaits for response. After communication is over we close the socket and exit the program.
### - udp:
 If mode was selected as `udp` we continue in function `udp_mode()`. There we again create client socket, but we don't connect to the server. After this we continue in loop which can only be ended by Interrupt signal `(C-c)`. In loop we null our buffer, and then we read client's message from stdin, then we create another buffer and add `REQUEST_OPCODE` as a byte at the start of message, followed by the lenght of client's message not including `\0`. We send this message to server with `sendto()` function. We null the buffer again. Then we wait for response from server with `recvfrom()` function. We validate the response from server. Firstly we check if the first byte is correct `RESPONSE_OPCODE`. Then if `STATS_CODE` is correct we will print the response to stdout.

## **Tests**
I managed to get server `ipkdp` to work on my machine:

<img src="./img/server.png" width="50%" height="50%">

From there I run som tests (I count compare tcp from my implementation to tcp from ncat)

 and here are the results:
(also can be found in the `img` folder in this repo)
- tcp

<img src="./img/tcp.png" width="50%" height="50%">

- tcp from ncat (ncat is a feature-rich networking utility which reads and writes data across networks from the command line)

<img src="./img/tcp_ncat.png" width="50%" height="50%">

- tcp interrupt signal -> server correctly responds

<img src="./img/tcpsignal.png" width="50%" height="50%">

- udp

<img src="./img/udp.png" width="50%" height="50%">

## **References**

[1] [Signal handler](https://stackoverflow.com/questions/4217037/catch-ctrl-c-in-c)

[2] [Tcp client](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Stubs/cpp/DemoTcp/client.cpp)

[3] [Udp client](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Stubs/cpp/DemoUdp/client.cpp)

[4] [Slides](https://moodle.vut.cz/pluginfile.php/550189/mod_folder/content/0/IPK2022-23L-04-TRANSPORT.pdf?forcedownload=0)%