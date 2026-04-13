import argparse
parser = argparse.ArgumentParser(description="scanner port");
#target URL
parser.add_argument("--target","-t",required=True,help="what address you want to scan")
# The beginning index of the target port range
parser.add_argument("-b",type=int)
# The end index of the target port range
parser.add_argument("-e",type=int)
# a port
parser.add_argument("-c",type=int)
# The number of the max threadings
parser.add_argument("-th",type=int,default=10)