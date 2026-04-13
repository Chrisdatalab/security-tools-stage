import Argparse
import Socket
import Display
def main():
    args=Argparse.parser.parse_args()
    if args.c is not None and (args.b is not None or args.e is not None):
        Argparse.parser.error("cannot use -c with -b/-e")
    if args.c is not None:
        #scan target port c
        result = Socket.check_banner(args.target, args.c,args.c,args.th)

    else:
        #scan target port range(begin,end)
        result = Socket.check_banner(args.target, args.b, args.e,args.th)

    Display.display_result(result)
if __name__=="__main__":
    main()