#!/usr/bin/env python3
import argparse, sys
from des import encrypt_bytes, decrypt_bytes

def readf(p): 
    with open(p,"rb") as f: return f.read()
def writef(p,d):
    with open(p,"wb") as f: f.write(d)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("mode", choices=["encrypt","decrypt"])
    p.add_argument("--key", required=True, help="16-hex-digit key (64-bit)")
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", dest="outfile", required=True)
    args=p.parse_args()
    if len(args.key)!=16:
        sys.exit("Key must be 16 hex digits")
    data=readf(args.infile)
    if args.mode=="encrypt":
        out=encrypt_bytes(data, args.key)
    else:
        out=decrypt_bytes(data, args.key)
    writef(args.outfile, out)
    print("Done:", args.mode, "->", args.outfile)

if __name__=="__main__":
    main()
