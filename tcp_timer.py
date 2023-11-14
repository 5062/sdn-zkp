import subprocess
from datetime import datetime

server_address = '10.0.0.2:22222'

# Spawn a tcpdump process with the appropriate arguments
tcpdump_proc = subprocess.Popen(
    ['tcpdump', '-l', 'tcp'],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    universal_newlines=True,
)

try:
    while True:
        syn_time = None
        server_ack_time = None

        # Read the output from the tcpdump process line by line
        for line in tcpdump_proc.stdout:
            # print(line)
            if f'> {server_address}: Flags [S]' in line:
                syn_time = datetime.strptime(line[:15], '%H:%M:%S.%f')
                print(f'syn_time: {syn_time}')
            elif f'{server_address} >' in line and 'Flags [P.]' in line and 'length 3\n' in line:
                server_ack_time = datetime.strptime(line[:15], '%H:%M:%S.%f')
                break

        if syn_time and server_ack_time:
            time_diff = server_ack_time - syn_time
            print(f'Time difference between SYN and server ACK: {time_diff}')
        else:
            print('Could not find SYN and server ACK in the tcpdump output')

except KeyboardInterrupt or Exception:
    tcpdump_proc.terminate()
