import math
N=21; TARGET=106.0; STRIPES=32; EXT=4
NON_WHIR=191_215-169_687          # measured: GKR, zerocheck, opened values, jagged, pvs
GKR=12_525
def bpq(r, regime):
    rho=2.0**-r
    if regime=="UDR": return -math.log2((1+rho)/2)
    if regime=="Johnson": return r/2.0
    if regime=="capacity": return float(r)
def whir(s=2, folds=(3,6,6), final=6, regime="UDR", pow_=22, digest=8, trees0=2):
    assert sum(folds)+final==N
    k=len(folds)-1
    sib=leaf=0; detail=[]
    consumed=0
    for j,f in enumerate(folds):
        rate=s+3*j
        dom=N-consumed+rate
        depth=dom-f
        width=(2**f)*(STRIPES if j==0 else EXT)
        q=math.ceil((TARGET-pow_)/bpq(rate,regime))
        t=trees0 if j==0 else 1
        sib+=t*q*depth; leaf+=t*q*width
        detail.append((q,depth,width,t))
        consumed+=f
    extras=sum(f*12 for f in folds)+8*k+16*0+ (2**final)*EXT + 256 + 8*(k+1) + 200
    return sib*digest+leaf+extras, sib, leaf, detail
rows=[
 ("measured Ziren: rate 1/4, UDR, 22-bit grind, folds 3/6/6", dict()),
 ("Johnson-bound list decoding", dict(regime="Johnson")),
 ("+ 48-bit query grinding", dict(regime="Johnson",pow_=48)),
 ("+ starting rate 1/256", dict(regime="Johnson",pow_=48,s=8)),
 ("+ folds 3/4/4/4 (narrower leaves)", dict(regime="Johnson",pow_=48,s=8,folds=(3,4,4,4))),
 ("+ 7-element (217-bit) digests", dict(regime="Johnson",pow_=48,s=8,folds=(3,4,4,4),digest=7)),
 ("capacity conjecture instead of Johnson", dict(regime="capacity",pow_=48,s=8,folds=(3,4,4,4),digest=7)),
]
base=None
print(f"{'scenario':<52}{'WHIR felts':>11}{'total felts':>12}{'bits':>11}{'adaptor MvB':>12}{'ACW MvB':>9}  queries/depth/leaf")
for name,kw in rows:
    w,sib,leaf,d=whir(**kw)
    tot=w+NON_WHIR; bits=tot*31
    if base is None: base=tot
    print(f"{name:<52}{w:>11,}{tot:>12,}{bits:>11,}{bits*2.14/1e6:>12.2f}{bits*11.38/1e6:>9.1f}  "+" ".join(f"{q}x{t}/{dp}/{wd}" for q,dp,wd,t in d))
w,_,_,_=whir(regime="Johnson",pow_=48,s=8,folds=(3,4,4,4),digest=7)
for name,nw in [("same, wrap without LogUp-GKR (non-WHIR minus 12,525)",NON_WHIR-GKR)]:
    tot=w+nw; bits=tot*31
    print(f"{name:<52}{w:>11,}{tot:>12,}{bits:>11,}{bits*2.14/1e6:>12.2f}{bits*11.38/1e6:>9.1f}")
print("calibration: measured WHIR felts 169,687; non-WHIR", NON_WHIR)
