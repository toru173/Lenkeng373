# Lenkeng373
Lenkeng373 capture script. See reverse engineering work conducted by Danman, https://danman.eu/blog

Requirements: Requires Pcapy and netifaces packages. Must be run as root.
Incompatible with Windows

```
Usage: hdmicapy.py [--input I] [--output AV] [--delay MS]
				   [--recvmac MAC] [--transmit IP] [--receive IP]
				   [--ffmpeg PATH] [--ffmpegout ARGS]
--input     i       Capture on network interface i
--output    av      Output "audio", "video" or "none". Default is audio & video
--delay     ms      Delay audio by ms milliseconds
--recvmac   MAC     Overide default MAC of transmitter
--transmit  IP      Overide default transmitter IP address
--receive   IP      Overide default receiver IP address
--ffmpeg    path    Path to FFmpeg
--ffmpegout args    Arguments to pass to FFmpeg
--heartbeat         transmitts heartbeat on interface i. For standalone operation
--help              Display this message
```
Example: sudo python hdmicap.py --input en1 --delay 100 --heartbeat


