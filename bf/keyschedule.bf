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
; IO  in:  mlen{1}  mesh{mlen}
; ss_dh{32}  ss_kem{32}
; p1len{1}  pt1{p1len}  p2len{1}  pt2{p2len}
; out: the ten frozen values in schedule order and raw:
; h_init{32}  h_after_mesh{32}  ck_after_dh{32}  ck_after_kem{32}
; ct1{p1len plus 16}  h_after_ct1{32}  ct2{p2len plus 16}  h_after_ct2{32}
; transport_key_i2r{32}  transport_key_r2i{32}
;
; The protocol name is a LITERAL exactly as it is a const in the Go port: a
; constant of the protocol rather than an input to it; Everything else comes
; from the broker's stdin and THE TWO SHARED SECRETS ARE INPUTS rather than
; something derived here __ which is precisely what lets the symmetric half
; be checked without X25519 or ML_KEM;
;
; ALL TEN FROZEN VALUES ARE REPRODUCED in 88 seconds;
;
; A VARIABLE INPUT IS CAPPED AT 207 BYTES which is a documented limit rather
; than an oversight; The largest length this file derives is 32 for the hash
; already on the tape plus a ciphertext of plen  plus  16 and that sum has to fit
; one cell; One more byte and it carries into a second and a 16 bit add with
; a borrow is real arithmetic in a language that has none; The vector's mesh
; is nine bytes and its plaintexts are fourteen;
;
; THE OUTPUT ORDER IS THE SCHEDULE ORDER which is what let this file be
; written one step at a time: the check script compares a PREFIX and names
; the first value missing so it reported "1 of 10" then "4 of 10" then
; ten; That is a property of the vector __ it freezes every intermediate
; rather than only the transport keys and a corpus publishing just the two
; keys would have forced an all_or_nothing implementation with no way to
; localise a fault;
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
; region   wall  base   holds
; 15    17     h_init  __ and ck_init the schedule says they are one
; 83    85     h after mixHash
; 151   153    ck after mixKey(ss_dh)
; 219   221    ck after mixKey(ss_kem)
; 287   289    the message key used by both seals
; 355   357    ct1 the first sealed frame
; 805   807    h after ct1
; 873   875    ct2 the second sealed frame
; 1323  1325   h after ct2
;
; A fixed region is 64 cells and the next wall sits two past its
; terminator so they step by 68; A CIPHERTEXT region is 446 because a
; 207 byte plaintext seals to 223 bytes and a pair costs two cells; The
; two transport keys get no region at all: nothing after the split needs
; them so they are relayed straight out as they arrive;
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
; ============================================================ ; mixHash: h = SHA256(h || mesh)
[-]++++++++++++++.------------.--...                           ; pipe  op 0e;  Handles 9 (read) and 10 (write);
,,,,,,,,,,,
[-]++++++++++++++.------------.--...                           ; pipe again;  Handles 11 (read) and 12 (write);
,,,,,,,,,,,
[-]+++++++++++++++.+++++++++++++++++++++++.-----------------   ; spawn sha256_bf;  len 0x26 = 38;  Proc 13;
  ---------------------.-....+..++..--..                       ; continued
.+++++++++.---------...
+.+++++++++++.------------...
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
                                                               ; read one length byte from the broker's stdin into
                                                               ; cell 7;
;
                                                               ; ONE BYTE NOT TWO AND THAT IS A DOCUMENTED LIMIT; A
                                                               ; variable input here is at most 223 bytes which is
                                                               ; what keeps every length in this file inside a single
                                                               ; cell: the routine wants 32 plus that for a mixHash
                                                               ; and 32 plus 223 is 255; One more byte and the length
                                                               ; would carry into a second cell and a 16 bit add with
                                                               ; a borrow is real arithmetic in a language with none;
                                                               ; The vector's mesh is nine bytes and its plaintexts
                                                               ; are fourteen;
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]<<<]
>>>
[
>>>,                                                           ; cell 7 takes it; the branch flag is consumed
<<<
[-]
]
<<<<
>>>>>>>                                                        ; copy cell 7 into cell 5 the countdown keeping cell 7
                                                               ; for the length
[-<<+>>>>>>+<<<<]
>>>>
[-<<<<+>>>>]
<<<<<<<<<<<
                                                               ; THE MESSAGE LENGTH in its own write frame: 32 for the
                                                               ; hash that is already on the tape plus the mesh the
                                                               ; caller is about to send; The high byte is a literal
                                                               ; zero which is the whole point of the 223 byte limit
                                                               ; above;
>>>>>>>
++++++++++++++++++++++++++++++++
<<<<<<<
[-]+++++++++++.---.--------.++++++++++.----------.....
>>>>>>>
.
<<<<<<<
[-].
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------   ; THE HASH SO FAR thirty two bytes off the tape in one
  ---------------------.++++++++++.----------.....             ; frame
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
                                                               ; THEN THE MESH forwarded from the caller a byte at a
                                                               ; time; It is never stored: it is read once and used
                                                               ; once which is the difference between this and the
                                                               ; digests;
>>>>>
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++++++++++.----------.....
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
>>>>>                                                          ; THE NEW HASH into its own region and out
[-]++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.+++++++++++.-----------...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>                                        ; continued
[>>]
>,
<+
[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<                                           ; continued
-
<[-]
]
>
]
<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------
  ---------------------.++.--.....                             ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>                                    ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<                                      ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
; ============================================================ ; mixKey: ck key = HKDF(ck ss_dh 64)
[-]++++++++++++++.------------.--...                           ; pipe  op 0e;  Handles 14 (read) and 15 (write);
,,,,,,,,,,,
[-]++++++++++++++.------------.--...                           ; pipe again;  Handles 16 (read) and 17 (write);
,,,,,,,,,,,
[-]+++++++++++++++.+++++++++++++++++++++.-------------------   ; spawn hkdf_bf;  len 0x24 = 36;  Proc 18;
  -----------------.-....+..++..--..                           ; continued
.++++++++++++++.--------------...
+.++++++++++++++++.-----------------...
..
+++.---.++++++++++++++++++++++++++++++++++++++++++++++++++++
  ++++++++++++++++++++++++++++++++++++++++++++++.++++.+++.     ; continued
------------------------------------------------------------
  --------------------------------------.-------.+++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  +++++++++++++++++++++++++++++++++++.+++.-------.++.-------   ; continued
  -------------------------------------------------.++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++.++++.           ; continued
,,,,,,,
                                                               ; THE FOUR LENGTHS in one frame: saltlen 32 ikmlen 32
                                                               ; infolen 0 okmlen 64; hkdf_bf reads all four before
                                                               ; any of the buffers;
[-]+++++++++++.+++.--------------.+++++++++++++++.----------
  -----.....++++++++++++++++++++++++++++++++.---------------   ; continued
  -----------------.++++++++++++++++++++++++++++++++.-------   ; continued
  -------------------------...++++++++++++++++++++++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++.-----------------------   ; continued
  -----------------------------------------.                   ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------   ; THE SALT which is the chaining key thirty two bytes
  ---------------------.+++++++++++++++.---------------.....   ; off the tape
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
                                                               ; AND THE REST OF THE SALT BUFFER; hkdf_bf takes
                                                               ; salt{256} ikm{256} info{256} as FIXED buffers and
                                                               ; looks only at the first saltlen and ikmlen bytes __
                                                               ; so the padding is required and is not optional; A
                                                               ; zero byte is the cheapest thing brainfuck emits: one
                                                               ; DOT on a cell already at zero which is why two
                                                               ; hundred and twenty four of them cost two hundred and
                                                               ; twenty four characters rather than a loop;
[-]+++++++++++.-------------------------------------.+++++++
  +++++++++++++++++++.+++++++++++++++.---------------.....     ; continued
................
................
................
................
................
................
................
................
................
................
................
................
................
................
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>                                                          ; THE INPUT KEY MATERIAL thirty two bytes forwarded
                                                               ; from the caller
[-]++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.+++++++++++++++.---------------.
  ....                                                         ; continued
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
[-]+++++++++++.-------------------------------------.+++++++   ; and the rest of its buffer
  +++++++++++++++++++.+++++++++++++++.---------------.....     ; continued
................
................
................
................
................
................
................
................
................
................
................
................
................
................
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; THE INFO BUFFER entirely empty: infolen was zero and
                                                               ; the schedule passes no context string; len 6  plus
                                                               ; 256 = 0x0106;
[-]+++++++++++.-----.-----.++++++++++++++.---------------...
  ..                                                           ; continued
................
................
................
................
................
................
................
................
................
................
................
................
................
................
................
................
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>                                                          ; THE FIRST THIRTY TWO BYTES OF THE OUTPUT are the new
                                                               ; chaining key
[-]++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.++++++++++++++++.----------------.
  ..+.-...                                                     ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                              ; continued
[>>]
>,
<+
[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<                                 ; continued
-
<[-]
]
>
]
<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------
  ---------------------.++.--.....                             ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                          ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                            ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; THE SECOND THIRTY TWO are the message key which this
                                                               ; step does not keep: the next mixKey replaces it
                                                               ; before anything encrypts with it;
>>>>>
[-]++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.++++++++++++++++.----------------.
  ..+.-...                                                     ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,
>>-
<[-]
]
>
]
<<<<<
; ============================================================ ; mixKey: ck key = HKDF(ck ss_kem 64)
[-]++++++++++++++.------------.--...                           ; pipe  op 0e;  Handles 19 (read) and 20 (write);
,,,,,,,,,,,
[-]++++++++++++++.------------.--...                           ; pipe again;  Handles 21 (read) and 22 (write);
,,,,,,,,,,,
[-]+++++++++++++++.+++++++++++++++++++++.-------------------   ; spawn hkdf_bf;  len 0x24 = 36;  Proc 23;
  -----------------.-....+..++..--..                           ; continued
.+++++++++++++++++++.-------------------...
+.+++++++++++++++++++++.----------------------...
..
+++.---.++++++++++++++++++++++++++++++++++++++++++++++++++++
  ++++++++++++++++++++++++++++++++++++++++++++++.++++.+++.     ; continued
------------------------------------------------------------
  --------------------------------------.-------.+++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  +++++++++++++++++++++++++++++++++++.+++.-------.++.-------   ; continued
  -------------------------------------------------.++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++.++++.           ; continued
,,,,,,,
                                                               ; THE FOUR LENGTHS in one frame: saltlen 32 ikmlen 32
                                                               ; infolen 0 okmlen 64; hkdf_bf reads all four before
                                                               ; any of the buffers;
[-]+++++++++++.+++.--------------.++++++++++++++++++++.-----
  ---------------.....++++++++++++++++++++++++++++++++.-----   ; continued
  ---------------------------.++++++++++++++++++++++++++++++   ; continued
  ++.--------------------------------...++++++++++++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++.-------------   ; continued
  ---------------------------------------------------.         ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------   ; THE SALT which is the chaining key from the step
  ---------------------.++++++++++++++++++++.---------------   ; before
  -----.....                                                   ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                          ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                            ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; AND THE REST OF THE SALT BUFFER which hkdf_bf
                                                               ; requires whether it looks at it or not: salt ikm and
                                                               ; info are FIXED 256 byte buffers and only the declared
                                                               ; prefix of each is read;
[-]+++++++++++.-------------------------------------.+++++++
  +++++++++++++++++++.++++++++++++++++++++.-----------------   ; continued
  ---.....                                                     ; continued
................
................
................
................
................
................
................
................
................
................
................
................
................
................
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>                                                          ; THE INPUT KEY MATERIAL thirty two bytes forwarded
                                                               ; from the caller
[-]++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++++++++++++++++++++.-----------
  ---------.....                                               ; continued
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
[-]+++++++++++.-------------------------------------.+++++++
  +++++++++++++++++++.++++++++++++++++++++.-----------------   ; continued
  ---.....                                                     ; continued
................
................
................
................
................
................
................
................
................
................
................
................
................
................
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.-----.-----.+++++++++++++++++++.-------------   ; THE INFO BUFFER entirely empty: the schedule passes
  -------.....                                                 ; no context string
................
................
................
................
................
................
................
................
................
................
................
................
................
................
................
................
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>                                                          ; THE FIRST THIRTY TWO BYTES are the new chaining key
[-]++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.+++++++++++++++++++++.------------
  ---------...+.-...                                           ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                    ; continued
[>>]
>,
<+
[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                       ; continued
-
<[-]
]
>
]
<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------
  ---------------------.++.--.....                             ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                  ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>                                                          ; AND THE SECOND THIRTY TWO are the message key kept
                                                               ; for the two seals
[-]++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.+++++++++++++++++++++.------------
  ---------...+.-...                                           ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>          ; continued
[>>]
>,
<+
[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<             ; continued
-
<[-]
]
>
]
<<<<<
; ============================================================ ; encryptAndHash: ct = AEAD(key nonce 0 h pt)
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]+++++++++++++++.+++++++++++++++++++++++++++++++++.-------   ; spawn chacha20poly1305_bf;  len 0x30 = 48;  Proc 28;
  -----------------------------------------.-....+..++..--..   ; continued
.++++++++++++++++++++++++.------------------------...
+.++++++++++++++++++++++++++.---------------------------...
..
+++.---.++++++++++++++++++++++++++++++++++++++++++++++++++++
  ++++++++++++++++++++++++++++++++++++++++++++++.++++.+++.     ; continued
------------------------------------------------------------
  --------------------------.-------------------.+++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  ++++++++++++++++++++++++++++++.+++++.-------.++.+++++.----   ; continued
  ---.-----------------------------------------------.--.+++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  +++.-.---.+++++++++++++.----------------------------------   ; continued
  --------------------------------------.++.---.+++++.------   ; continued
  -.++++++++++++++++++++++++++++++++++++++++++++++++++++.+++   ; continued
  +.                                                           ; continued
,,,,,,,
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------   ; the message key both seals use thirty two bytes off
  ---------------------.+++++++++++++++++++++++++.----------   ; the tape
  ---------------.....                                         ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>      ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<        ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; THE NONCE: four zero bytes then the counter 64 bit
                                                               ; little endian; mixKey reset it so the first seal is
                                                               ; under nought and the second under one __ which the
                                                               ; vector freezes only as two different ciphertexts and
                                                               ; which had to come from reading the Go reference
                                                               ; rather than from the numbers;
[-]+++++++++++.+++++++.------------------.++++++++++++++++++
  +++++++.-------------------------.....                       ; continued
............
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; THE ADDITIONAL DATA IS THE TRANSCRIPT HASH which is
                                                               ; what binds the seal to everything that came before
                                                               ; it: alen 32 then h off the tape;
[-]+++++++++++.---.--------.+++++++++++++++++++++++++.------
  -------------------.....++++++++++++++++++++++++++++++++.-   ; continued
  -------------------------------.                             ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------
  ---------------------.+++++++++++++++++++++++++.----------   ; continued
  ---------------.....                                         ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>                                    ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<                                      ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; read one length byte from the caller into cell 7 and
                                                               ; keep two copies of it: cell 5 counts a forward down
                                                               ; to nothing and cell 8 survives that so the lengths
                                                               ; derived from it afterwards can still be computed;
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]<<<]
>>>
[
>>>[-],
<<<
[-]
]
<<<<
>>>>>
[-]
>>>
[-]
>>>
[-]
<<<<
[-<<+>>>+>>>+<<<<]
>>>>
[-<<<<+>>>>]
<<<<<<<<<<<
[-]+++++++++++.---.--------.+++++++++++++++++++++++++.------   ; the plaintext length then the plaintext forwarded a
  -------------------.....                                     ; byte at a time
>>>>>>>
.
<<<<<<<
[-].
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.+++++++++++++++++++++++++.------
  -------------------.....                                     ; continued
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
                                                               ; THE SEALED FRAME is plen  plus  16 bytes: the
                                                               ; ciphertext and then its tag; The count is derived
                                                               ; from the length the caller sent rather than assumed;
>>>>>
[-]
>>>
[-<<<+>>>>>>+<<<]
>>>
[-<<<+>>>]
<<<<<<
++++++++++++++++
<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.++++++++++++++++++++++++++.-------
  -------------------...+.-...                                 ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>                                                          ; continued
[>>]
>,
<+
[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
-
<[-]
]
>
]
<<<<<
>>>>>>>                                                        ; and out in one frame whose own length is plen  plus
                                                               ; 22
[-]
<<<<<<<
>>>>>>>>
[-<+>>>>+<<<]
>>>
[-<<<+>>>]
<<<<
++++++++++++++++++++++
<<<<<<<
[-]+++++++++++.
>>>>>>>
.
<<<<<<<
[-].++.--.....
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>                                                      ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<                                                        ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
; ============================================================ ; mixHash: h = SHA256(h || ct)
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]+++++++++++++++.+++++++++++++++++++++++.-----------------   ; spawn sha256_bf;  len 0x26 = 38;  Proc 33;
  ---------------------.-....+..++..--..                       ; continued
.+++++++++++++++++++++++++++++.-----------------------------
  ...                                                          ; continued
+.+++++++++++++++++++++++++++++++.--------------------------
  ------...                                                    ; continued
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
                                                               ; the message length: 32 for the hash on the tape plus
                                                               ; the ciphertext's plen  plus  16;  That sum is why a
                                                               ; variable input here is capped at 207 bytes;
>>>>>>>
[-]
<<<<<<<
>>>>>>>>
[-<+>>>>+<<<]
>>>
[-<<<+>>>]
<<<<
++++++++++++++++++++++++++++++++++++++++++++++++
<<<<<<<
[-]+++++++++++.---.--------.++++++++++++++++++++++++++++++.-
  -----------------------------.....                           ; continued
>>>>>>>
.
<<<<<<<
[-].
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------   ; the hash so far
  ---------------------.++++++++++++++++++++++++++++++.-----   ; continued
  -------------------------.....                               ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>                                    ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<                                      ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>>>                                                        ; then the ciphertext in a frame of plen  plus  22
[-]
<<<<<<<
>>>>>>>>
[-<+>>>>+<<<]
>>>
[-<<<+>>>]
<<<<
++++++++++++++++++++++
<<<<<<<
[-]+++++++++++.
>>>>>>>
.
<<<<<<<
[-].++++++++++++++++++++++++++++++.-------------------------
  -----.....                                                   ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>                                                      ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<                                                        ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>                                                          ; the new hash into its own region and out
[-]++++++++++++++++++++++++++++++++
<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.+++++++++++++++++++++++++++++++.--
  -----------------------------...+.-...                       ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>              ; continued
[>>]
>,
<+
[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                 ; continued
-
<[-]
]
>
]
<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------
  ---------------------.++.--.....                             ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>          ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<            ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
; ============================================================ ; encryptAndHash: ct = AEAD(key nonce 1 h pt)
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]+++++++++++++++.+++++++++++++++++++++++++++++++++.-------   ; spawn chacha20poly1305_bf;  len 0x30 = 48;  Proc 38;
  -----------------------------------------.-....+..++..--..   ; continued
.++++++++++++++++++++++++++++++++++.------------------------
  ----------...                                                ; continued
+.++++++++++++++++++++++++++++++++++++.---------------------
  ----------------...                                          ; continued
..
+++.---.++++++++++++++++++++++++++++++++++++++++++++++++++++
  ++++++++++++++++++++++++++++++++++++++++++++++.++++.+++.     ; continued
------------------------------------------------------------
  --------------------------.-------------------.+++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  ++++++++++++++++++++++++++++++.+++++.-------.++.+++++.----   ; continued
  ---.-----------------------------------------------.--.+++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  +++.-.---.+++++++++++++.----------------------------------   ; continued
  --------------------------------------.++.---.+++++.------   ; continued
  -.++++++++++++++++++++++++++++++++++++++++++++++++++++.+++   ; continued
  +.                                                           ; continued
,,,,,,,
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------   ; the message key both seals use thirty two bytes off
  ---------------------.+++++++++++++++++++++++++++++++++++.   ; the tape
  -----------------------------------.....                     ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>      ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<        ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; THE NONCE: four zero bytes then the counter 64 bit
                                                               ; little endian; mixKey reset it so the first seal is
                                                               ; under nought and the second under one __ which the
                                                               ; vector freezes only as two different ciphertexts and
                                                               ; which had to come from reading the Go reference
                                                               ; rather than from the numbers;
[-]+++++++++++.+++++++.------------------.++++++++++++++++++
  +++++++++++++++++.-----------------------------------.....   ; continued
....+.-.......
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; THE ADDITIONAL DATA IS THE TRANSCRIPT HASH which is
                                                               ; what binds the seal to everything that came before
                                                               ; it: alen 32 then h off the tape;
[-]+++++++++++.---.--------.++++++++++++++++++++++++++++++++
  +++.-----------------------------------.....++++++++++++++   ; continued
  ++++++++++++++++++.--------------------------------.         ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------
  ---------------------.+++++++++++++++++++++++++++++++++++.   ; continued
  -----------------------------------.....                     ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>          ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<            ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; read one length byte from the caller into cell 7 and
                                                               ; keep two copies of it: cell 5 counts a forward down
                                                               ; to nothing and cell 8 survives that so the lengths
                                                               ; derived from it afterwards can still be computed;
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]<<<]
>>>
[
>>>[-],
<<<
[-]
]
<<<<
>>>>>
[-]
>>>
[-]
>>>
[-]
<<<<
[-<<+>>>+>>>+<<<<]
>>>>
[-<<<<+>>>>]
<<<<<<<<<<<
[-]+++++++++++.---.--------.++++++++++++++++++++++++++++++++   ; the plaintext length then the plaintext forwarded a
  +++.-----------------------------------.....                 ; byte at a time
>>>>>>>
.
<<<<<<<
[-].
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.+.-...+.-...
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++++++++++++++++++++++++++++++++
  +++.-----------------------------------.....                 ; continued
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
                                                               ; THE SEALED FRAME is plen  plus  16 bytes: the
                                                               ; ciphertext and then its tag; The count is derived
                                                               ; from the length the caller sent rather than assumed;
>>>>>
[-]
>>>
[-<<<+>>>>>>+<<<]
>>>
[-<<<+>>>]
<<<<<<
++++++++++++++++
<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.++++++++++++++++++++++++++++++++++
  ++.------------------------------------...+.-...             ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>    ; continued
[>>]
>,
<+
[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<       ; continued
-
<[-]
]
>
]
<<<<<
>>>>>>>                                                        ; and out in one frame whose own length is plen  plus
                                                               ; 22
[-]
<<<<<<<
>>>>>>>>
[-<+>>>>+<<<]
>>>
[-<<<+>>>]
<<<<
++++++++++++++++++++++
<<<<<<<
[-]+++++++++++.
>>>>>>>
.
<<<<<<<
[-].++.--.....
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>                                                          ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <                                                            ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
; ============================================================ ; mixHash: h = SHA256(h || ct)
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]+++++++++++++++.+++++++++++++++++++++++.-----------------   ; spawn sha256_bf;  len 0x26 = 38;  Proc 43;
  ---------------------.-....+..++..--..                       ; continued
.+++++++++++++++++++++++++++++++++++++++.-------------------
  --------------------...                                      ; continued
+.+++++++++++++++++++++++++++++++++++++++++.----------------
  --------------------------...                                ; continued
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
                                                               ; the message length: 32 for the hash on the tape plus
                                                               ; the ciphertext's plen  plus  16;  That sum is why a
                                                               ; variable input here is capped at 207 bytes;
>>>>>>>
[-]
<<<<<<<
>>>>>>>>
[-<+>>>>+<<<]
>>>
[-<<<+>>>]
<<<<
++++++++++++++++++++++++++++++++++++++++++++++++
<<<<<<<
[-]+++++++++++.---.--------.++++++++++++++++++++++++++++++++
  ++++++++.----------------------------------------.....       ; continued
>>>>>>>
.
<<<<<<<
[-].
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------   ; the hash so far
  ---------------------.++++++++++++++++++++++++++++++++++++   ; continued
  ++++.----------------------------------------.....           ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>          ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<            ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>>>                                                        ; then the ciphertext in a frame of plen  plus  22
[-]
<<<<<<<
>>>>>>>>
[-<+>>>>+<<<]
>>>
[-<<<+>>>]
<<<<
++++++++++++++++++++++
<<<<<<<
[-]+++++++++++.
>>>>>>>
.
<<<<<<<
[-].++++++++++++++++++++++++++++++++++++++++.---------------
  -------------------------.....                               ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>                                                          ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <                                                            ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>                                                          ; the new hash into its own region and out
[-]++++++++++++++++++++++++++++++++
<<<<<
>>>>>
[
<<<<<
[-]++++++++++.--.--------.++++++++++++++++++++++++++++++++++
  +++++++.-----------------------------------------...+.-...   ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                  ; continued
[>>]
>,
<+
[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                     ; continued
-
<[-]
]
>
]
<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------
  ---------------------.++.--.....                             ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>              ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
; ============================================================ ; split: i2r r2i = HKDF(ck empty 64)
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]++++++++++++++.------------.--...
,,,,,,,,,,,
[-]+++++++++++++++.+++++++++++++++++++++.-------------------   ; spawn hkdf_bf;  len 0x24 = 36;  Proc 48;
  -----------------.-....+..++..--..                           ; continued
.++++++++++++++++++++++++++++++++++++++++++++.--------------
  ------------------------------...                            ; continued
+.++++++++++++++++++++++++++++++++++++++++++++++.-----------
  ------------------------------------...                      ; continued
..
+++.---.++++++++++++++++++++++++++++++++++++++++++++++++++++
  ++++++++++++++++++++++++++++++++++++++++++++++.++++.+++.     ; continued
------------------------------------------------------------
  --------------------------------------.-------.+++++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++   ; continued
  +++++++++++++++++++++++++++++++++++.+++.-------.++.-------   ; continued
  -------------------------------------------------.++++++++   ; continued
  ++++++++++++++++++++++++++++++++++++++++++++.++++.           ; continued
,,,,,,,
                                                               ; saltlen 32 ikmlen ZERO infolen 0 okmlen 64; The split
                                                               ; takes no input key material at all __ it derives the
                                                               ; two directional transport keys from the chaining key
                                                               ; alone which is what makes them a function of the
                                                               ; whole transcript and nothing else;
[-]+++++++++++.+++.--------------.++++++++++++++++++++++++++
  +++++++++++++++++++.--------------------------------------   ; continued
  -------.....++++++++++++++++++++++++++++++++.-------------   ; continued
  -------------------.....++++++++++++++++++++++++++++++++++   ; continued
  ++++++++++++++++++++++++++++++.---------------------------   ; continued
  -------------------------------------.                       ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.+++++++++++++++++++++++++++.-----------------   ; the salt is the chaining key after both mixKey steps
  ---------------------.++++++++++++++++++++++++++++++++++++   ; continued
  +++++++++.---------------------------------------------...   ; continued
  ..                                                           ; continued
>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>   ; continued
  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>                ; continued
[>.>]
<<[<<]
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<   ; continued
  <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<                  ; continued
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.-------------------------------------.+++++++
  +++++++++++++++++++.++++++++++++++++++++++++++++++++++++++   ; continued
  +++++++.---------------------------------------------.....   ; continued
................
................
................
................
................
................
................
................
................
................
................
................
................
................
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.-----.-----.+++++++++++++++++++++++++++++++++   ; the input key material buffer entirely padding:
  +++++++++++.---------------------------------------------.   ; ikmlen was zero
  ....                                                         ; continued
................
................
................
................
................
................
................
................
................
................
................
................
................
................
................
................
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
[-]+++++++++++.-----.-----.+++++++++++++++++++++++++++++++++   ; and the info buffer also empty
  +++++++++++.---------------------------------------------.   ; continued
  ....                                                         ; continued
................
................
................
................
................
................
................
................
................
................
................
................
................
................
................
................
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
                                                               ; THE TWO TRANSPORT KEYS relayed straight out rather
                                                               ; than stored: nothing after this needs them so they
                                                               ; never touch a region;
>>>>>
[-]++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.++++++++++++++++++++++++++++++++++
  ++++++++++++.---------------------------------------------   ; continued
  -...+.-...                                                   ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++.--.....
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
>>>>>
[-]++++++++++++++++++++++++++++++++
[
<<<<<
[-]++++++++++.--.--------.++++++++++++++++++++++++++++++++++
  ++++++++++++.---------------------------------------------   ; continued
  -...+.-...                                                   ; continued
>[-]+,<,,
>>>>+<<<
[[-]>>>[-]>[-]<<<<]
>>>
[
<,<<<
[-]+++++++++++.----.-------.++.--.....
>>>.<<<
>[-]+,
>>>>>>>>
[-],
<<<<<<<<<
,
>>>>>>>>>
[-<<<<<<<<<,>>>>>>>>>]
<<<<<<<<<
>>>>>-
<[-]
]
>
]
<<<<<
                                                               ; wait  op 10 on the LAST process handle blocking and
                                                               ; exit with its code;
;
                                                               ; ONE WAIT AT THE END RATHER THAN ONE PER STEP; Nothing
                                                               ; is closed in this file so nothing needs reaping to
                                                               ; free a slot and the broker kills and reaps whatever
                                                               ; is left when the program exits; What the wait buys is
                                                               ; the exit code: ask for a routine that is not there
                                                               ; and the interpreter cannot exec it the child exits
                                                               ; 127 and this program exits non_zero rather than
                                                               ; reporting success having computed nothing; An earlier
                                                               ; step failing that way shows up as a wrong digest
                                                               ; which the vector catches;
[-]++++++++++++++++.----------.------.++++++++++++++++++++++
  ++++++++++++++++++++++++++.-------------------------------   ; continued
  -----------------.....                                       ; continued
,,,,
>>>,<<<
,,
[-]++.-.-.                                                     ; exit  op 02 len 1 and the code is the routine's own
>>>.<<<
,,,
