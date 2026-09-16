; keyschedule_poke __ the BMX key schedule in brainfuck;
;
; Reproduces spec/corpus/transcripts/keyschedule_json by SEQUENCING bfsodium
; routines: a brainfuck program holds the transcript hash and the chaining key
; on its own tape spawns an interpreter on the right routine for each step
; feeds it bytes reads the answer back and carries it into the next step;
; No shell in the middle;
;
; That is the claim neither project underneath can make on its own; bfsodium
; proves each routine correct against Cryptol and the RFCs; brainstem proves
; the broker works across two kernels; NEITHER proves the join; This file is
; the join;
;
; THE SCHEDULE from security_md section 5 matching go/keyschedule exactly:
;
; h  = SHA256(protocol_name)        ck = h
; h  = SHA256(h || mesh)                                    mixHash
; ck key = HKDF(salt=ck ikm=ss_dh  64)                    mixKey
; ck key = HKDF(salt=ck ikm=ss_kem 64)                    mixKey
; ct1 = AEAD(key nonce 0 aad=h pt1);  h = SHA256(h || ct1)
; ct2 = AEAD(key nonce 1 aad=h pt2);  h = SHA256(h || ct2)
; i2r r2i = HKDF(salt=ck ikm=empty 64)                    split
;
; The nonce is four zero bytes then a 64 bit little endian counter and mixKey
; RESETS it __ so ct1 seals under nonce 0 and ct2 under nonce 1; That came
; from reading the Go reference rather than from a guess: a vector freezes the
; ciphertexts not the counter that made them;
;
; TWO THINGS MAKE THIS WRITABLE and both are worth knowing before editing;
;
; NOTHING IS EVER CLOSED so every handle is a literal; brainstem hands out
; the lowest free slot and bumps that slot's generation on CLOSE so a program
; that closes a pipe mid_conversation has to track generations and emit
; 04 00 01 00 where it used to emit 04 00 00 00; This program never needs to:
; a bfsodium primitive READS AN EXACT KNOWN BYTE COUNT and never relies on
; end of input which is a rule in its CONVENTIONS __ so no routine here ever
; needs its pipe closed to know it is done and every handle below stays
; generation zero; Nine steps five handles each handles 4 to 48 all
; literal; BS_HANDLES is 128;
;
; NOTHING IS EVER OVERWRITTEN so every region is written once and read as
; often as needed; Overwriting a 32 byte value on the tape means clearing 64
; cells first and a clear that runs at the wrong moment is invisible; Cells
; are free and the tape is unbounded so each value gets its own region and
; the old one simply stays there; h_init is also ck_init __ the schedule says
; so __ and is the one region that serves as both;
;
; IO  in:  nothing yet __ the protocol name is a literal and init takes no
; input; The later steps read mesh ss_dh ss_kem and the two
; plaintexts from stdin;
; out: h_init{32}
;
; The protocol name is a LITERAL exactly as it is a const in the Go port: a
; constant of the protocol rather than an input to it;
;
; WHAT IS IMPLEMENTED SO FAR: init; One of the ten frozen values and every
; piece of machinery the other eight need __ the region idioms the literal
; handles the reply drain; The remaining steps land one at a time each
; checked against its own frozen value first and the check script compares
; however many this program emits; The vector exposing all ten intermediates
; is what makes that possible; a corpus freezing only the transport keys
; would have been far harder to write against;
;
; TAPE MAP
; cell 0 is the working cell: every EMIT and every READ uses it;
; cell 1 holds the status byte of a read;
; cell 3 holds one byte in flight;
; cell 4 is the branch flag: set before a read cleared by an END status;
; cell 5 counts down a read or a forward of known length;
; cell 9 holds a reply's declared payload length while it is drained;
;
; A REGION is 32 pairs: a flag cell that is always one then the byte; The
; flag is what makes it walkable __ brainfuck's only test is whether a cell is
; zero and a digest contains zero bytes so a run of raw bytes cannot be
; traversed; Two idioms reach every region and neither needs a length:
;
; store   R base  { gt  gt }  gt    lt   plus   { lt  lt }  L wall      one byte into the next slot
; emit    R base  { gt ; gt }   lt  lt  { lt  lt }  L wall          every byte in order
;
; "{ lt  lt }" walks left over the flags and comes to rest on the WALL a cell two
; before the base that is never written; That is why the emit idiom steps back
; twice first: it lands on the terminator which is zero and has to get onto
; a flag before the walk will run; Both idioms therefore work on a region of
; ANY length which matters for the ciphertexts later;
;
; region  wall  base   holds
; 15    17     h_init  __ and ck_init which the schedule says is the same
; 83    85     h after mixHash          not yet written
; 151   153    ck after mixKey(ss_dh)   not yet written
; 219   221    ck after mixKey(ss_kem)  not yet written
; 287   289    the message key          not yet written
;
; The key from the FIRST mixKey is read and dropped: the schedule replaces it
; before anything encrypts with it so it gets no region;
;
; INDENTATION IS LOAD BEARING; A comment indented by two or more spaces
; annotates the frame that follows it; a flush one is the file talking about
; itself;
;
; Frames transcribed by hand from brainstem's ABI_md sections 3 7_10 to 7_16;
;
; hello  op 01 len 10 want major 1 and MINOR 1 __ every spawn below sends
; a zero length path which only a 1_1 broker reads as "the interpreter you
; are already running under";
+.+++++++++.----------.+++++++++++++++++++++++++++++++++++++
  +++++++++++++++++++++++++++++.+++++++++++++++++.+.-------.   ; continued
  ----------------------------------------------------------   ; continued
  ------------------.-.+.-...                                  ; continued
,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
  ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,              ; continued
; ============================================================ ; init: h = SHA256(protocol_name)
[-]++++++++++++++.------------.--...                           ; pipe  op 0e flags 0;  Handles 4 (read) and 5 (write);
,,,,,,,,,,,
[-]++++++++++++++.------------.--...                           ; pipe again;  Handles 6 (read) and 7 (write);
,,,,,,,,,,,
                                                               ; spawn  op 0f len 0x26 = 38;  dir ffffffff is the
                                                               ; broker's working directory flags 0 nfdmap 2 nargv 2
                                                               ; nenv 0 reserved 0;  Proc 8;
[-]+++++++++++++++.+++++++++++++++++++++++.-----------------
  ---------------------.-....+..++..--..                       ; continued
.++++.----...
+.++++++.-------...
..
+++.---.++++++++++++++++++++++++++++++++++++++++++++++++++++
  ++++++++++++++++++++++++++++++++++++++++++++++.++++.+++.     ; continued
------------------------------------------------------------
  ------------------------------------.---------.+++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++.-----------   ; continued
  .-------.-----------------------------------------------.+   ; continued
  ++.+.--------.++++++++++++++++++++++++++++++++++++++++++++   ; continued
  ++++++++.++++.                                               ; continued
,,,,,,,
                                                               ; THE WHOLE INPUT IN ONE WRITE FRAME;  sha256_bf wants
                                                               ; len{2} LE then the message and the message is the 48
                                                               ; byte protocol name so the frame carries fifty bytes
                                                               ; and its length is 6 plus that: 0x38 = 56; One frame
                                                               ; rather than fifty because every byte is a LITERAL __
                                                               ; there is nothing from the tape to interleave which is
                                                               ; what forces a byte at a time elsewhere;
[-]+++++++++++.+++++++++++++++++++++++++++++++++++++++++++++
  .--------------------------------------------------------.   ; continued
  +++++.-----.....                                             ; continued
++++++++++++++++++++++++++++++++++++++++++++++++.-----------
  -------------------------------------.                       ; continued
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  ++++++.+++++++++++++++++++++++++++++++++++++++++++++.-.---   ; continued
  ------.------------------------.++++++++++++++++++++++++.+   ; continued
  +++++++++++++.-----------.---------.----------------------   ; continued
  -------.+++++++++++.+++++++++++.+++++++.++++++++++++++++++   ; continued
  +++++.----------------------------------------------------   ; continued
  ---------------.++++++++++++++++++++++++++++++++++++++++++   ; continued
  ++.                                                          ; continued
-------.--------------------------------------.+++..----.+++
  +++++.++++++++++++++++++++.-.-.------.++++++++.-----------   ; continued
  -----------.-.++.+++++++++++++++++++++++++++++++++++++++.-   ; continued
  ---------------------------.                                 ; continued
+++++++++++++++++++++++++++++++++++++.-------.--------------
  ----------------.+++++++++++++++++++++++++++++++++++++.---   ; continued
  ----.-----------------.+++++++++++++++++++++++++++++++.---   ; continued
  .+++++++++++++.--------------------------.------------.---   ; continued
  --------.-------.---------------.+++.+.                      ; continued
                                                               ; THE REPLY IS DRAINED BY ITS DECLARED LENGTH never by
                                                               ; an assumed one; A write that succeeds answers with
                                                               ; nwritten{2}; a write that FAILS answers with no
                                                               ; payload because ABI rule I6 says an error reply never
                                                               ; carries one; Reading five unconditionally swallows
                                                               ; the next reply's first two the moment a write fails
                                                               ; and every frame after it is shifted;
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; THE DIGEST into the h_init region thirty two bytes;
                                                               ; Counted AND status checked: the count says how many
                                                               ; bytes a digest has so a short answer comes out short
                                                               ; and visibly wrong; the status says when to stop
                                                               ; asking so a routine that died is not waited on for
                                                               ; ever;
>>>>>
++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.++++++.------...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
                                                               ; out to the region on to the first slot not yet
                                                               ; written and let the comma land the byte straight
                                                               ; there __ a comma writes wherever the pointer is so
                                                               ; the byte never has to be carried across the tape
>>>>>>>>>>>>>
[>>]
>,
<+
[<<]
<<<<<<<<<<                                                     ; home along the flags to the wall then to the counter
-
<[-]
]
>
]
<<<<<
                                                               ; h_init OUT in one write frame: the header is literal
                                                               ; and the bytes come off the tape so the data is
                                                               ; emitted by walking the region rather than by EMIT;
                                                               ; write op 0b len 6  plus  32 = 0x26 handle 2 is the
                                                               ; broker's stdout;
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------
  ---------------------.++.--.....                             ; continued
>>>>>>>>>>>>>>>>>
[>.>]
<<[<<]
<<<<<<<<<<<<<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; wait  op 10 handle 8 flags 0 __ blocking;  The reply
                                                               ; is status two length bytes then state{1} code{1}
                                                               ; signal{1} reserved{1};
;
                                                               ; THE ROUTINE'S EXIT CODE BECOMES THIS PROGRAM'S which
                                                               ; is the difference between a driver and a pipe: ask
                                                               ; for a routine that is not there and the interpreter
                                                               ; cannot exec it the child exits 127 and this program
                                                               ; exits non_zero rather than reporting success having
                                                               ; computed nothing;
[-]++++++++++++++++.----------.------.++++++++.--------.....
,,,,
>>>,<<<                                                        ; cell 3 takes the code
,,
                                                               ; exit  op 02 len 1 and the code is the routine's own;
                                                               ; Nothing is closed here or anywhere: the broker
                                                               ; reclaims every handle when the program exits and
                                                               ; closing one earlier is what would have forced this
                                                               ; file to track generations;  See the header;
[-]++.-.-.
>>>.<<<
,,,
