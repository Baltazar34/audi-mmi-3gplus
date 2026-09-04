#!/usr/bin/env python3
"""orion_layer_survey.py — dekoduje šeme sadržaja svakog Orion .ATLAS sloja.

Container (HEADER/CONTAINER/INDEX/codec) je vec resen i zajednicki. Ovaj alat
raspakuje prvih N graph/data chunkova jednog sloja i ispisuje njihove logicke
seme (composite imena, clanovi, tipovi) preko vec dokazanog NavCore
`parseDescriptions` parsera iz `orion_psd_reference_profile`.
"""
from __future__ import annotations
import argparse, json, struct, sys, zlib, lzma
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_psd_reference_profile import parse_logical_schema  # noqa: E402

LZMA_FILTERS=[{"id":lzma.FILTER_LZMA1,"lc":3,"lp":0,"pb":2,"dict_size":1<<16}]

def decompress(codec,data,expected):
    if codec==1: return data[:expected]
    if codec==2: return zlib.decompress(data)[:expected]
    e=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=LZMA_FILTERS)
    return e.decompress(data)[:expected]

def iter_chunks(path,limit):
    size=path.stat().st_size; off=0; n=0
    with path.open("rb") as f:
        while n<limit:
            f.seek(off); head=f.read(0x40)
            if len(head)<0x40: break
            nl=head[0]
            if nl==0 or nl>0x0f: break
            name=head[1:1+nl].decode('ascii','replace')
            bs=struct.unpack_from("<I",head,0x10)[0]
            if bs<0x20 or off+bs>size: break
            if name=="CONTAINER":
                codec=head[0x20]
                f.seek(off); blk=f.read(bs)
                if codec==1:
                    payload=blk[0x21:bs-16]
                    try: dec=payload
                    except Exception: dec=None
                else:
                    cnt=blk[0x21]; do=0x22+cnt*8
                    pairs=[struct.unpack_from("<II",blk,0x22+i*8) for i in range(cnt)]
                    csize,usize=pairs[0]
                    try: dec=decompress(codec,blk[do:do+csize],usize)
                    except Exception: dec=None
                if dec: yield off,dec; n+=1
            off+=bs

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("atlas",type=Path)
    ap.add_argument("--limit",type=int,default=30)
    args=ap.parse_args()
    comps=Counter(); members=Counter(); ok=0; fail=0; samples=[]
    for off,dec in iter_chunks(args.atlas,args.limit):
        sch=parse_logical_schema(dec)
        if not sch: fail+=1; continue
        ok+=1
        for c in sch.get("composites",[]):
            comps[c["name"]]+=1
            for m in c.get("members",[]):
                members[f"{c['name']}.{m['name']}:{m['type_code']}"]+=1
        if len(samples)<3:
            samples.append({"offset":f"0x{off:x}","map":sch.get("map_name"),
                            "composites":[c["name"] for c in sch.get("composites",[])]})
    print(json.dumps({"atlas":args.atlas.name,"chunks_ok":ok,"chunks_fail":fail,
        "composites":dict(comps.most_common(25)),
        "members":dict(members.most_common(40)),
        "samples":samples},indent=2,ensure_ascii=False))

if __name__=="__main__": sys.exit(main())
