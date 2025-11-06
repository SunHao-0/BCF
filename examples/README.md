## Example programs

A set of safe programs incorrectly rejected by the current verifier. One may build the program, load it with our enhencement, and see how the loader, the solver, the kernel verifier, and the proof checker interact with each other.

#### Build and Boot

Note that we have already provided a build script `scripts/build.sh` to automatically download the source, patch, and build the kernel, bpftool, cvc5.

Just:
```
> ./scripts/build.sh all
```
will build everything under a `build` directory and copy the artifacts to the `output` directory.

Alternatively, you may download `bpf-next` and checkout to `4cb4897bb49a4` (the base test commit); other HEAD should also work as the patches are mostly adding code.

Apply the patches from each set:
```
git am $(ls ./patches-kernel/set1:verifier_and_initial_checker_support/*.patch | grep -v '/0000-')
git am $(ls ./patches-kernel/set2:add_core_proof_rules/*.patch | grep -v '/0000-')
git am $(ls ./patches-kernel/set3:add_boolean_proof_rules/*.patch | grep -v '/0000-')
git am $(ls ./patches-kernel/set4:/add_bv_proof_rules/*.patch | grep -v '/0000-')
git am $(ls ./patches-kernel/set5:/bpftool_libbpf_support/*.patch | grep -v '/0000-')
```

Build the kernel and download the disk image we provided (which contains the prebuilt `bpftool` and `cvc5` with BCF support). Extract the images in `imgs`.

Boot the system with `qemu`, with our script:

```
./scripts/boot_vm.sh
```

The script boots the qemu with the kernel located under `output/bzImage`, share the current directory to the guest vm. Login to VM via:

```
ssh -i ./imgs/bookworm.id_rsa -p 10024 root@localhost
```

Inside the VM, enter the shared dir `bcf`; Try loading the programs from `examples`:

```
> cd bcf
> ~/bpftool -P /usr/bin/cvc5 prog load ./examples/unreachable_arsh.bpf.o /sys/fs/bpf
> # optionally enable the debug option and see the proof checking process
> ~/bpftool -d -P /usr/bin/cvc5 prog load ./examples/unreachable_arsh.bpf.o /sys/fs/bpf
```

The example loading log is as follows:

```
Using prover: cvc5
libbpf: loading object from ./bpf-progs/collected/shift_constraint.bpf.o
libbpf: elf: section(3) tracepoint/syscalls/sys_enter_execve, size 96, link 0, flags 6, type=1
...
Proving the path condition...
(set-logic QF_BV)
(declare-fun v0 () (_ BitVec 64))
(assert (bvule ((_ zero_extend 32) (bvlshr (bvand ((_ extract 31 0) v0) (_ bv255 32)) (_ bv1 32))) (_ bv4 64)))
(check-sat)
(exit)
sat
Proving the refine condition...
(set-logic QF_BV)
(declare-fun v0 () (_ BitVec 64))
(assert (let ((t10 (bvand ((_ extract 31 0) v0) (_ bv255 32)))) (and (bvule ((_ zero_extend 32) (bvlshr t10 (_ bv1 32))) (_ bv4 64)) (bvsgt ((_ extract 31 0) (bvadd (_ bv0 64) ((_ zero_extend 32) t10))) (_ bv15 32)))))
(check-sat)
(exit)
unsat
(
; WARNING: add trust rewrite step for bv-bitwise-slicing
; Proof produced: 622 steps, 13756 bytes
)
libbpf: prog 'shift_constraint': -- BEGIN PROG LOAD LOG --
func#0 @0
Live regs before insn:
      0: .......... (85) call bpf_get_prandom_u32#7
      1: 0......... (bc) w0 = w0
      2: 0......... (54) w0 &= 255
      3: 0......... (bc) w1 = w0
      4: 01........ (bf) r2 = r10
      5: 012....... (07) r2 += -16
      6: 012....... (0f) r2 += r0
      7: .12....... (77) r1 >>= 1
      8: .12....... (25) if r1 > 0x4 goto pc+1
      9: ..2....... (71) r0 = *(u8 *)(r2 +0)
     10: .......... (b7) r0 = 0
     11: 0......... (95) exit
0: R1=ctx() R10=fp0
; asm volatile("call 0x7\n\t" @ shift_constraint.bpf.c:23
0: (85) call bpf_get_prandom_u32#7    ; R0=scalar()
1: (bc) w0 = w0                       ; R0=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
2: (54) w0 &= 255                     ; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff))
3: (bc) w1 = w0                       ; R0=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff)) R1=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff))
4: (bf) r2 = r10                      ; R2=fp0 R10=fp0
5: (07) r2 += -16                     ; R2=fp-16
6: (0f) r2 += r0
mark_precise: frame0: last_idx 6 first_idx 0 subseq_idx -1 
mark_precise: frame0: regs=r0 stack= before 5: (07) r2 += -16
mark_precise: frame0: regs=r0 stack= before 4: (bf) r2 = r10
mark_precise: frame0: regs=r0 stack= before 3: (bc) w1 = w0
mark_precise: frame0: regs=r0 stack= before 2: (54) w0 &= 255
mark_precise: frame0: regs=r0 stack= before 1: (bc) w0 = w0
mark_precise: frame0: regs=r0 stack= before 0: (85) call bpf_get_prandom_u32#7
7: R0=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff)) R2=fp(off=-16,smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff))
7: (77) r1 >>= 1                      ; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=127,var_off=(0x0; 0x7f))
8: (25) if r1 > 0x4 goto pc+1         ; R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=4,var_off=(0x0; 0x7))
9: (71) r0 = *(u8 *)(r2 +0)
invalid variable-offset read from stack R2 var_off=(0x0; 0xff) off=-16 size=1
checking 622 proof steps
(#0 REFL () (((_ extract 7 0) @t0)) (bool_eq(2) ((_ extract 7 0) @t0) ((_ extract 7 0) @t0)))
(#1 EVALUATE () (((_ extract 23 0) @t3)) (bool_eq(2) ((_ extract 23 0) @t3) (_ bv0 24)))
(#2 CONG (@p1 @p0) (@t2097816) (bool_eq(2) (bv_concat(2) @t6 @t1) (bv_concat(2) @t1412 @t1)))
(#3 REFL () (((_ extract 7 0) @t0)) (bool_eq(2) ((_ extract 7 0) @t0) ((_ extract 7 0) @t0)))
(#4 REFL () (((_ extract 23 0) @t12)) (bool_eq(2) ((_ extract 23 0) @t12) ((_ extract 23 0) @t12)))
(#5 EVALUATE () ((_ bv0 56)) (bool_eq(2) (_ bv0 56) (_ bv0 56)))
(#6 SYMM (@p5) () (bool_eq(2) (_ bv0 56) (_ bv0 56)))
(#7 CONG (@p6) (@t385876280) (bool_eq(2) ((_ extract 23 0) @t1419) ((_ extract 23 0) @t12)))
...
(#621 RESOLUTION (@p620 @p618 @p605) (((_ extract 7 0) @t0), @t228, @t232) false)
proof accepted

9: R0=scalar(id=1,smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff)) R1=scalar(smin=smin32=0,smax=umax=smax32=umax32=4,var_off=(0x0; 0x7)) R2=fp(off=-16,smin=smin32=0,smax=umax=smax32=umax32=15,var_off=(0x0; 0xf)) R10=fp0
9: (71) r0 = *(u8 *)(r2 +0)           ; R0=scalar(smin=smin32=0,smax=umax=smax32=umax32=255,var_off=(0x0; 0xff)) R2=fp(off=-16,smin=smin32=0,smax=umax=smax32=umax32=15,var_off=(0x0; 0xf))
; return 0; @ shift_constraint.bpf.c:34
10: (b7) r0 = 0                       ; R0=0
11: (95) exit
(0) frame 0 insn 9 +live -8,-16 
(0) frame 0 insn 8 +live -8,-16 
(0) frame 0 insn 1 +live -8,-16 
(0) frame 0 insn 0 +live -8,-16 
(0) live stack update done in 2 iterations

from 8 to 10: safe
verification time 42070 usec
stack depth 16
processed 14 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 0
-- END PROG LOAD LOG --
libbpf: prog 'shift_constraint': pinned at '/sys/fs/bpf/test/shift_constraint'
```

#### (Optional) Build cvc5

Download cvc5 git repo and checkout to `f7db8faac6639980ed61a1920042ded79cd15e21`, and apply the patch under `patches-solver`.

```
> ./configure.sh production --static --best --gpl --auto-download
> cd build && make -j`nproc`
```

Built the binary as static to run it easily inside the VM.

Try out the QF_BV unsat formulas from [here](https://github.com/testsmt/semantic-fusion-seeds/tree/master/QF_BV/unsat).

```
> # Dump proof in bcf format
> ./build/bin/cvc5 --proof-print-conclusion  --bv-print-consts-as-indexed-symbols --proof-format=bcf --proof-granularity=dsl-rewrite --bcf-proof-out=bcf.out  --dump-proofs /path/to/formula.smt2
>
> # Check the proof with our checker
> ./bcf-checker -v ./bcf.out
>
> #Dump the proof in readable text format
> ./build/bin/cvc5 --proof-print-conclusion  --bv-print-consts-as-indexed-symbols --proof-format=cpc --proof-granularity=dsl-rewrite --dump-proofs /path/to/formula.smt2
```
