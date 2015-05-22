'''-------------------------------------79----------------------------------'''

'''
PYTHON PACKET SNIFFER FROM http://oss.coresecurity.com/projects/pcapy.html.

MODIFIED EXTENSIVELY TO CAPTURE HDMI FROM LENKENG LKV373 HDMI IP EXTENDER BY
TORU173. REQUIRES PCAPY AND NETIFACES PYTHON PACKAGES. MUST RUN AS ROOT

A HUGE AMOUNT OF RESEARCH GATHERED BY danman, PUBLISHED IN HIS BLOG AT
https://danman.eu/blog/reverse-engineering-lenkeng-hdmi-over-ip-extender/
SOME ADDITIONAL RESEARCH CONDUCTED BY THE AUTHER

INTENDED USE: LENKENG HDMI TO IP TRANSMITTER ON ONE ETHERNET PORT, THIS
SOFTWARE TO PROCESS PACKETS, FFMPEG INSTALLED AND CALLABLE TO RETRANSMIT
ON ANOTHER NETWORK INTERFACE. FIRST ETHERNET PORT MUST BE ASSIGNED IP IN
RANGE 192.168.0.0 /16, OR DEFAULT IP OF TRANSMITTER NEEDS TO BE CHANGED.

TODO:
    - Write more complete help. Requires python-pcapy, python-netifaces to
        be installed on fresh Debian install using apt-get
    - Allow user-defined args for FFmpeg
    - Allow user overide of default MAC of receiver
    - Write a good 'Help' function, to be activated when no ARGS passed
        - Or when 'Help,' 'help,' '?,' 'H' or 'man' passed as args
    - test on PPC, x86, x86_64, OS X, *nix, VMs etc. BECAUSE OF MKFIFO,
      WILL NOT RUN ON WINDOWS. Although investigation needed
    - General clean up
    - more robust error handling. OS Independant advice when unable to
      import package.
    - move FIFO read/write pointer increment logic into try: except clause
        - when implemented results in odd sound synch errors?
    - add heartbeat_transmit code to send when heartbeart received from receiver
      rather than standalone thread
    - use framerate packet (received on port 2067) for frame pacing. only write frame to
      FIFO when this packet received.
'''

from struct import *
import socket
import sys
import os
import time
import atexit
import multiprocessing
import subprocess
try:
    import pcapy
except:
    # Add OS dependant advice
    sys.stderr.write("Pcapy not found. Please install from https://github.com/CoreSecurity/pcapy" + newline())
    quit()

try:
    import netifaces
except:
    # Add OS dependant advice
    sys.stderr.write("Netifaces not found. Please install from https://pypi.python.org/pypi/netifaces" + newline())
    quit()


@atexit.register
def cleanup () :
    # Close pipes at exit, no matter the exit state
    try :
        os.unlink(audio_fifo_location)
        os.unlink(video_fifo_location)
    except:
        pass

    try :
        os.remove(audio_fifo_location)
        os.remove(video_fifo_location)
    except :
        pass


def newline () :
    return '\r\n'


def error_header () :
    return "[ " + time.ctime() + " ] Error: "


def args_error () :
    return 'Invalid Argument' + newline () + \
            args_help()


def args_help () :
    # Model after https://github.com/Jalle19/node-ffmpeg-mpegts-proxy
    return 'Requirements: Requires Pcapy and netifaces packages. Must be run as root.' + newline() + \
           'Incompatible with Windows' + newline() + \
           'Usage: pcapy.py [--input I] [--output AV] [--delay MS]' + newline() + \
           '                [--recvmac MAC] [--transmit IP] [--receive IP]' + newline() + \
           '                [--ffmpeg PATH] [--ffmpegout ARGS]' + newline() + \
           '    --input     i       Capture on network interface i' + newline() + \
           '    --output    av      Output "audio", "video" or "none". Default is audio & video' + newline() + \
           '    --delay     ms      Delay audio by ms Milliseconds' + newline() + \
           '    --recvmac   MAC     Overide default MAC of transmitter' + newline() + \
           '    --transmit  IP      Overide default transmitter IP address' + newline() + \
           '    --receive   IP      Overide default receiver IP address' + newline() + \
           '    --ffmpeg    path    Path to FFmpeg' + newline() + \
           '    --ffmpegout args    Arguments to pass to FFmpeg' + newline() + \
            newline() + \
           ' Example: sudo python pycap.py --input en1 --delay 100 --receive 192.168.168.55'


def heartbeat_transmitter (TRANSMITTER_IP, RECEIVER_IP, HEARTBEAT_PORT, debug_level = None) :
    
    # Sends required heartbeat signal to TRANSMITTER_IP on HEARTBEAT_PORT
    # Sends from whatever, passed as RECEIVER_IP
    
    # The below have already been tested and found to produce no error
    heartbeat_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    heartbeat_socket.bind((RECEIVER_IP, HEARTBEAT_PORT))

    # HEARTBEAT FORMAT NOTES FROM http://danman.eu/blog/?p=110
    # ADDITIONAL NOTES: https://danman.eu/blog/reverse-engineering-lenkeng-hdmi-over-ip-extender/#comment-67
    
    heartbeat_header = '5446367a60' # -63 = Sender, -60 = Receiver
    sender_receiver = '02' # 01 = Sender, 02 = Receiver
    heartbeat_padding = '0000'
    heartbeat_counter = '0000' # Counter not implemented
    receiver_sequence = '000303010026000000'
    receiver_uptime = '00000000' # Uptime not implemented
    # Remaining flags not yet implemented
    
    message = heartbeat_header + sender_receiver + heartbeat_padding + heartbeat_counter + receiver_sequence + receiver_uptime
    message = message.decode('hex')
    
    while 1 :
        if debug_level == 3 :
            sys.stdout.write("Transmitting Heartbeat on " + RECEIVER_IP + newline())
        
        try:
            heartbeat_socket.sendto(message, (TRANSMITTER_IP, HEARTBEAT_PORT))
        except Exception as e :
            if debug_level is not None :
                sys.stderr.write(error_header() + e[0] + newline())
        time.sleep(1)


def parse_packet (input_source, packet_type = None, fifo_location = None, delay_ms = 0, debug_level = None) :

    # Opening input_source has already been tested and found to work
    
    # Attempt to open network interface for raw reading. Requires root.
    # Arguments here are:
    # device
    # snaplen (maximum number of bytes to capture _per_packet_)
    # promiscious mode (1 for true)
    # timeout (in milliseconds)
    
    # NEED TO PUT IN EXCEPTION HANDLER in case of transmitter reset:
    # PcapError: e: No such device exists (BIOCSETIF failed: Device not configured)

    capture = pcapy.open_live(input_source, 65536 , 1 , 0)
    
    framecount = 0
    
    # MAC address of HDMI transmitter (appears to be the same for all units).
    # Formating is per normal MAC address, without colons. For example, the below
    # is equivelent to 00:0B:78:00:60:01.
    transmitter = '000b78006001'.decode('hex')
    
    if packet_type == "video" :
    
        previous_frame_number = -1
        previous_chunk = -1
        previous_frame = ''
        current_frame = ''
        

    if packet_type == "audio" :
        # Calculate audio delay in number of packets. 992 bytes per packet (after header),
        # 4 bytes per sample, 48,000 * 2 channel samples per second.
        # Approx 2.6 packets per millisecond. Prepopulate with '0x00000000'
        
        if delay_ms > 0:
            delay_packets = int((1000 / (48000/124)) * delay_ms)
            # Write data package size - 16 byte header = 992 bytes of '0x00'
            audio_delay_fifo = [('00'.decode('hex') * 992)] * (delay_packets + 1)
            
            audio_delay_fifo_top = delay_packets
            audio_delay_fifo_read_pointer = 0
            audio_delay_fifo_write_pointer = audio_delay_fifo_top

        else :
            # Set FIFO to single frame size
            audio_delay_fifo = [('00'.decode('hex') * 992)]

            audio_delay_fifo_top = 0
            audio_delay_fifo_read_pointer = 0
            audio_delay_fifo_write_pointer = audio_delay_fifo_top


    if fifo_location :
        if debug_level is not None :
            sys.stderr.write("Attempting to open " + fifo_location + newline())
        fifo = open(fifo_location, 'w')
        
        if debug_level is not None :
            sys.stderr.write("Successfully opened " + fifo_location + " for writing" + newline())


    current_timestamp = 0
    signal_fps = 0
    encoded_fps = 0
    
    if debug_level is not None :
        sys.stderr.write("Capturing " + packet_type + " packets on interface " + input_source + newline())


    while 1 :

        # NEED TO PUT IN ERROR HANDLING in case of removing usb interface:
        # PcapError: The interface went down
        (header, packet) = capture.next()
        
        #parse ethernet header
        eth_length = 14
        
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        eth_source = eth_header[6:12]
        
        # FOR SOME REASON, PROTOCOL NUMBER CHANGES WITH PLATFORM. ENDIANESS ISSUE?
        # HDMI TRANSMITTER APPEARS TO USE PROTOCAL NUMBER 2048 ON DEBIAN PPC,
        # 8 (AS EXPECTED) ON OS X 10.9.4
        IP_protocol_number = 8
        
        if (eth_protocol == IP_protocol_number) & (eth_source == transmitter) :
            
            # Parse IP header
            # Take first 20 characters for the ip header
            ip_header = packet[eth_length : 20 + eth_length]
            
            # Now unpack them
            iph = unpack('!BBHHHBBH4s4s', ip_header)
            
            
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            iph_length = ihl * 4
            
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
            
            # UDP packets (only expected packets from this device - good sanity
            # check)
            if protocol == 17 :
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u : u + 8]
                
                # Unpack them
                udph = unpack('!HHHH', udp_header)
                
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]
                
                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size
                
                # Get data from the packet
                data = packet[h_size : ]
                
                if (dest_port == 2066) & (packet_type == "audio") :
                    # Packet contains PCM audio data. Handle accordingly.
                    # AUDIO FORMAT NOTES FROM http://danman.eu/blog/?p=110
                    # Audio is signed 32 bit PCM, big endian, stereo, 48Khz with
                    # 16 bye header. Remove header, write remainder to internal FIFO
                    # prepopulated with '0x00'. Once internal fifo full, write
                    # to external fifo

                    audio_delay_fifo[audio_delay_fifo_write_pointer] = data[16 : ]

                    try:
                        fifo.write(audio_delay_fifo[audio_delay_fifo_read_pointer])
                    except IOError:
                        if debug_level is not None :
                            sys.stderr.write(error_header() + "Cannot write to audio FIFO" + newline())
            
                    audio_delay_fifo_read_pointer += 1
                    audio_delay_fifo_write_pointer += 1
                            
                    if audio_delay_fifo_read_pointer > audio_delay_fifo_top :
                        audio_delay_fifo_read_pointer = 0
                            
                    if audio_delay_fifo_write_pointer > audio_delay_fifo_top :
                        audio_delay_fifo_write_pointer = 0


                if (dest_port == 2067) & (packet_type == "heartbeat") :

                    # Receive frame count message from transmitter. Occurs once, at the end of frame.
                    # See https://danman.eu/blog/reverse-engineering-lenkeng-hdmi-over-ip-extender/#comment-67
                    
                    # CAN WE USE THIS PACKET AS A FRAME PACING MECHANISM?
                    
                    framecount += 1
    
                    if framecount > 29 :
                        # Update encoded_fps every 30 frames. Too much variation updating every frame.
            
                        previous_timestamp = current_timestamp
                        current_timestamp = time.time()
                        time_delta = current_timestamp - previous_timestamp
                        
                        encoded_fps = int(30 / time_delta)
                        
                        framecount = 0


                if (dest_port == 2068) & (packet_type == "video") :
                    # Packet contains MJPEG image data. Handle accordingly.
                    # FRAME FORMAT NOTES FROM http://danman.eu/blog/?p=110
                    # | 2B - Frame number | 2B - Frame chunk number | data |
                    #
                    # - Frame number - (unsigned short, big endian) all chunks within one
                    #   JPEG frame have same frame number, increments by 0x01
                    # - Frame chunk number - (unsigned short, big endian) first image chunk
                    #   is 0x0000, increments by 0x01, last chunk has MSB set to 1.
                    #   Header is removed, write remainder temporary file. When full file
                    #   compiled, write to FIFO.
                    
                    # PERHAPS CHANGE - INSTEAD OF DROPPING WHOLE FRAME, JUST WRITE '0x00' in
                    # place of the missing chunk. Would need to use the below. Next step would
                    # be to take the same section from previous frame and stitch in
                    #
                    # chunk_delta = current_chunk - previous chunk
                    #
                    # if chunk_delta > 1 :
                    #    # Indicates dropped frame
                    #    current_frame += ('00'.decode('hex') * 1012) * (chunk_delta - 1)
                    
                    
                    frame_number = unpack('>H', data[0 : 2])[0]
                    frame_chunk = unpack('>H', data[2 : 4])[0]
                    
                    last_chunk = 0
                    dropped_frame = 0
                    dropped_frame_error = ''

                    
                    if frame_chunk > 32768 :
                        # Last chunk (MSB set to 1). Set flag, adjust chunk number
                        last_chunk = 1
                        frame_chunk = frame_chunk - 32768
                
                    if (frame_chunk != previous_chunk + 1) :
                        # Missed a chunk. Drop frame. Do not output partial frame.
                        dropped_frame = 1
                        dropped_frame_error = "missed a chunk. Current chunk is " + \
                            str(frame_chunk) + ", previous chunk was " + \
                                str(previous_chunk)
                    
                    if (frame_number > previous_frame_number + 1) & (dropped_frame == 0) :
                        # Missed a frame. Drop this frame, and consider it the previous frame
                        dropped_frame = 1
                        dropped_frame_error = "missed a frame. Current frame is " + \
                            str(frame_number) + ", previous frame was " + \
                                str(previous_frame_number)
                
                    if dropped_frame == 1 :
                        # Action dropped frame, if necessary.
                        if previous_chunk == -1 :
                            pass
                        else :
                            if previous_frame != '' :
                                # Previously captured a frame. Write that frame to the FIFO instead of the dropped frame
                                try:
                                    fifo.write(previous_frame)
                                except IOError :
                                    # Fifo closed: Broken Pipe.
                                    if debug_level is not None :
                                        sys.stderr.write(error_header() + "Dropped frame, cannot write to FIFO. Current frame is " + str(frame_number) + newline())
                            if debug_level is not None :
                                sys.stderr.write(error_header() + "Dropped frame, " + dropped_frame_error + newline())
                        previous_frame_number = frame_number
                        current_frame = ''
                        previous_chunk = -1
                    
                    else :
                        # Add chunk to existing frame.
                        current_frame = current_frame + data[4 : ]
                        previous_chunk = frame_chunk
            
                    if last_chunk & (dropped_frame == 0) :
                        # Successfully capture whole JPEG frame. Attempt to write to FIFO
                        try:
                            previous_frame = current_frame
                            fifo.write(current_frame)
                        except IOError :
                            # Fifo closed: Broken Pipe. Receiving app probably quit.
                            if debug_level is not None :
                                sys.stderr.write(error_header() + "Cannot write to video FIFO" + newline())

                        # Clean up
                        previous_chunk = -1
                        previous_frame_number = frame_number
                        dropped_frame = 0
                        dropped_frame_error = ''
                        last_chunk = 0
                        current_frame = ''


                if (dest_port == 48689) & (packet_type == "heartbeat") :
                    
                    # Receive heartbeat message from transmitter, parse useful stats.
                    # See https://danman.eu/blog/reverse-engineering-lenkeng-hdmi-over-ip-extender/#comment-67
                    
                    signal_present = unpack('>B', data[27 : 28])[0]
                    signal_width = unpack('>H', data[28 : 30])[0]
                    signal_height = unpack('>H', data[30 : 32])[0]
                    signal_fps = unpack('>H', data[32 : 34])[0]
                    encoded_width = unpack('>H', data[34 : 36])[0]
                    encoded_height = unpack('>H', data[36 : 38])[0]
                    uptime = unpack('>L', data[40 : 44])[0] # IN MILLISECONDS
                    receiver_present = unpack('>B', data[50 : 51])[0]
                    
                    if signal_present == 3 :
                        signal_present = "Yes"
                    else :
                        signal_present = "No"
                    
                    if signal_present == "No" :
                        sys.stderr.write("No HDMI signal detected" + newline())
                    
                    if receiver_present == 0 :
                        # Cannot detect receiver (or heartbeat from this script)
                       sys.stderr.write("No heartbeart detected" + newline())
                    
                    signal_fps = signal_fps / 10.0 # FPS correction, found by varying FPS at source.
                    
                    seconds = uptime / 1000
                    minutes, seconds = divmod(seconds, 60)
                    hours, minutes = divmod(minutes, 60)
                    days, hours = divmod(hours, 24)
                    
                    if debug_level == 2 :
                        # Need to write better way to output stats
                        print "HDMI signal being received?: " + signal_present
                        print "Signal width: " + str(signal_width)
                        print "Signal height: " + str(signal_height)
                        print "Signal FPS: " + str(signal_fps)
                        print "Encoded width: " + str(encoded_width)
                        print "Encoded hight: " + str(encoded_height)
                        print "Encoded FPS: " + str(encoded_fps)
                        print "Uptime: {} day(s), {} hours, {} minutes, {} seconds".format(days, hours, minutes, seconds)


def main (argv) :

    # Check for windows
    if 'win' in sys.platform.lower() :
        if sys.platform == 'darwin' :
            # 'darwin' (OS X) is supported
            pass
        else :
            # Result contains 'win' - probably windows something
            sys.stderr.write("Windows is not supported at this time" + newline())
            quit()


    # Argument Defaults:
    if sys.platform == 'darwin' :
        input_source = 'en0'
    else:
        input_source = 'eth0'


    video_fifo_location = "/tmp/videofifo"
    audio_fifo_location = "/tmp/audiofifo"

    output_method = "audio and video"
    delay_ms = 0

    # default is for FFMPEG in same folder as Python script.
    FFMPEG_BIN = "./ffmpeg"

    # Begin tokenizing arguements. Cast all to lower case
    for i in argv :
        argv[argv.index(i)] = argv[argv.index(i)].lower()
    
    if "--help" in argv or \
       "-help" in argv or \
       "-h" in argv or \
       "h" in argv or \
       "--?" in argv or \
       "-?" in argv or \
       "?" in argv :
        print args_help()
        quit()

    
    if "--debug" in argv :
        try:
            if argv[argv.index("--debug") + 1] == "stats" :
                debug_level = 2
            if argv[argv.index("--debug") + 1] == "heartbeat" :
                debug_level = 3
            else:
                debug_level = 1
        except :
            # No args for "--debug"
            debug_level = 1
    else :
        debug_level = None

    if "--input" in argv :
        # User specified alternate input interface. Default is eth0 (or en0)
        if argv[argv.index("--input") + 1] in netifaces.interfaces() :
            input_source = argv[argv.index("--input") + 1]
        else :
            if debug_level is not None :
                sys.stderr.write(args_error() + newline())
                sys.stderr.write("Interface " + argv[argv.index("--input") + 1] + " not available" + newline())
            quit()

    if "--output" in argv :
        # User specified AV output type. Default is both
        if argv[argv.index("--output") + 1] == "audio" :
            output_method = "audio"
        elif argv[argv.index("--output") + 1] == "video" :
            output_method = "video"
        elif argv[argv.index("--output") + 1] == "none" :
            output_method = "none"
        else :
            sys.stderr.write(args_error() + newline())
            quit()

    if "--delay" in argv :
        # Check argv[argv.index("--delay") + 1] is int
        # NEED TO IMPLEMENT ERROR CHECKING/HANDLING
        delay_ms = int(argv[argv.index("--delay") + 1])

    if "--heartbeat" in argv :
        transmit_heartbeat = 1
    else :
        transmit_heartbeat = 0

    if "--transmit" in argv :
        # NEED TO PUT IN ERROR CHECKING FOR IP ADDRESS
        transmitter_ip = argv[argv.index("--transmit") + 1]
    else :
        transmitter_ip = '192.168.168.55'

    if "--receive" in argv :
        print "--receive not yet implemented"
        quit()

    if "--recvmac" in argv :
        print "--recvmac not yet implemented"
        quit()


    if "--ffmpeg" in argv :
        # Passes raw string. NEED TO IMPLEMENT ERROR CHECKING/HANDLING
        # SO AS NOT TO ALLOW MALFORMED PATH VARIABLE
        FFMPEG_BIN = argv[argv.index("--ffmpeg") + 1]

    if "--ffmpegout" in argv :
        # Passes raw strin to ffmpeg. NEED TO IMPLEMENT ERROR CHECKING/HANDLING
        ffmpeg_output_string = argv[argv.index("--ffmpegout") + 1]
    else:
        ffmpeg_output_string = 'udp://127.0.0.1:5010?ttl=1'


    # CREATE TWO PIPES USING OS.MKFIFO(), WRITES INFORMATION TO FFMPEG. INCOMPATIBLE WITH WINDOWS

    try:
        os.mkfifo(audio_fifo_location)
    except Exception as e :
        # Fifo exists. Action
        if debug_level is not None :
            sys.stderr.write(error_header() + e[1] + newline())
        try :
            os.remove(audio_fifo_location)
            os.mkfifo(audio_fifo_location)
        except Exception as e :
            if debug_level is not None :
                sys.stderr.write(error_header() + e[1] + newline())

    try:
        os.mkfifo(video_fifo_location)
    except:
        # Fifo exists. Action
        if debug_level is not None :
            sys.stderr.write(error_header() + e[1] + newline())
        try :
            os.remove(video_fifo_location)
            os.mkfifo(video_fifo_location)
        except Exception as e :
            if debug_level is not None :
                sys.stderr.write(error_header() + e[1] + newline())

    # Attempt to open network interface for raw reading. Requires root.
    # Arguments here are:
    # device
    # snaplen (maximum number of bytes to capture _per_packet_)
    # promiscious mode (1 for true)
    # timeout (in milliseconds)

    try:
        capture = pcapy.open_live(input_source, 65536 , 1 , 0)
    except Exception as e :
        sys.stderr.write("Could not open live input source. Are you root?" + newline())
        if debug_level is not None :
            sys.stderr.write(error_header() + e[0] + newline())
        quit()

    # Attempt to bind to heartbeat port.
    # Get IP address allocated to interface input_source to which to broadcast heartbeat
    try:
        input_source_ip = netifaces.ifaddresses(input_source)[2][0]['addr']
    except Exception as e:
        sys.stderr.write("Unable to obtain IP address for " + input_source + newline())
        if debug_level is not None :
            sys.stderr.write(error_header() + str(e[0]) + newline())
        quit()

    try:
        heartbeat_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        heartbeat_socket.bind((input_source_ip, 48689))
    except Exception as e :
        sys.stderr.write("Cannot transmit heartbeat - socket in use." + newline())
        if debug_level is not None :
            sys.stderr.write(error_header() + e[1] + newline())
        quit()

    # Successfully opened socket. Close it now, reopen later.
    heartbeat_socket.close()

    audio_capture_thread = multiprocessing.Process(target = parse_packet, args = (input_source, "audio", audio_fifo_location, delay_ms, debug_level) )
    video_capture_thread = multiprocessing.Process(target = parse_packet, args = (input_source, "video", video_fifo_location, 0, debug_level) )
    heartbeat_thread = multiprocessing.Process(target = heartbeat_transmitter, args = (transmitter_ip, input_source_ip, 48689, debug_level) )
    heartbeat_capture_thread = multiprocessing.Process(target = parse_packet, args = (input_source, "heartbeat", None, 0, debug_level) )

    command = [FFMPEG_BIN,
           '-f', 's32be',
           '-ar', '48000',
           '-ac', '2',
           '-i', '/tmp/audiofifo',
           '-f', 'mjpeg',
           '-i', '/tmp/videofifo',
           '-f', 'mpegts',
           '-qscale:a', '1',
           '-qscale:v', '1',
           ffmpeg_output_string]

    if output_method == "audio" :
        audio_capture_thread.start()

    if output_method == "video" :
        video_capture_thread.start()

    if output_method == "audio and video" :
        audio_capture_thread.start()
        video_capture_thread.start()

    if output_method == "none" :
        # Don't start capture of anything. For testing heartbeat.
        pass

    heartbeat_capture_thread.start()

    if transmit_heartbeat == 1 :
        heartbeat_thread.start()

    sys.stdout.write("Capturing input on interface " + input_source + ". Press Ctrl + C to abort" + newline())



    if output_method is not "none" :
        try :
            ffmpeg_subprocess = subprocess.Popen(command, stdout = sys.stdout, stderr = sys.stderr)
        except Exception as e :
            sys.stderr.write("Cannot find FFmpeg binary at " + FFMPEG_BIN + newline())
            if debug_level is not None :
                sys.stderr.write(error_header() + e[1] + newline())
            quit()

    while 1:
        try :
            time.sleep(0.5)
        
        except KeyboardInterrupt :
            
            if output_method == "audio" :
                audio_capture_thread.terminate()

            if output_method == "video" :
                video_capture_thread.terminate()

            if output_method == "audio and video" :
                audio_capture_thread.terminate()
                video_capture_thread.terminate()

            if transmit_heartbeat == 1 :
                heartbeat_thread.terminate()

            if output_method is not "none" :
                ffmpeg_subprocess.terminate()

            heartbeat_capture_thread.terminate()
            
            cleanup()

            quit()


if __name__ == "__main__" :
    main(sys.argv)